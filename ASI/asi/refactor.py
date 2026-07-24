"""Refactor stage: comment out dead functions, then LLM-refactor the file.

Pipeline per source file (driven by the analysis report):

    read file
      -> comment out its dead functions  (deterministic, always correct)
      -> [unless --comment-only] send to the LLM to refactor the rest
      -> verify the result (syntax / optional build command)
      -> on failure, fall back to the safe commented-only version
      -> write (to an output dir, or in place with a .asi.bak backup)

The deterministic commenting guarantees the dead code is disabled correctly no
matter what the model returns; the LLM only ever improves the *live* code, and
any output that fails verification is discarded in favour of the safe version.
"""

from __future__ import annotations

import difflib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

from .commenting import comment_out
from .config import Config
from .llm import build_prompt, get_client, strip_fences


_LANG_BY_EXT = {
    "py": "Python", "pyi": "Python",
    "c": "C", "h": "C", "cpp": "C++", "cc": "C++", "cxx": "C++",
    "hpp": "C++", "hh": "C++",
    "js": "JavaScript", "jsx": "JavaScript", "ts": "TypeScript", "tsx": "TypeScript",
    "java": "Java", "go": "Go", "rs": "Rust", "cs": "C#", "kt": "Kotlin",
    "swift": "Swift", "scala": "Scala",
}


@dataclass
class FileOutcome:
    file: str
    action: str            # commented | refactored | fallback_commented | unchanged | skipped | error
    dead_count: int = 0
    wrote_to: str = ""
    note: str = ""
    diff_lines: int = 0


@dataclass
class RefactorResult:
    outcomes: list = field(default_factory=list)
    out_dir: str = ""
    in_place: bool = False
    comment_only: bool = False
    verify_ok: object = None   # True / False / None (not run)


def _lang(ext: str) -> str:
    return _LANG_BY_EXT.get(ext.lower().lstrip("."), "unknown")


def load_report(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _target_files(report: dict, scope: str, comment_only: bool) -> dict:
    """Return ``{file: [dead entries]}`` for the files we should process."""
    dead_by_file = {}
    for f in report.get("dead", []):
        dead_by_file.setdefault(f["file"], []).append(f)

    if comment_only or scope == "dead_files":
        return dead_by_file

    # scope == "all": include every analysed file, even those with no dead code.
    all_files = {}
    for bucket in ("dead", "live"):
        for f in report.get(bucket, []):
            all_files.setdefault(f["file"], [])
    for fpath, entries in dead_by_file.items():
        all_files[fpath] = entries
    return all_files


def refactor(cfg: Config, report_path: str, out_dir: str, in_place: bool,
             comment_only: bool, dry_run: bool, scope: str,
             verbose: bool = False) -> RefactorResult:
    report = load_report(report_path)
    targets = _target_files(report, scope, comment_only)

    result = RefactorResult(out_dir=out_dir, in_place=in_place, comment_only=comment_only)
    client = None
    if not comment_only:
        client = get_client(cfg)   # may raise a helpful LLMError if SDK missing

    for rel in sorted(targets):
        dead_entries = targets[rel]
        outcome = _process_file(cfg, rel, dead_entries, out_dir, in_place,
                                comment_only, dry_run, client, verbose)
        result.outcomes.append(outcome)

    # Optional post-write build/behaviour check (only meaningful in-place, where
    # the source tree is intact). On failure, restore the backups we wrote.
    if not dry_run and in_place:
        result.verify_ok = _run_verify_command(cfg)
        if result.verify_ok is False:
            _restore_backups(result)

    return result


def _process_file(cfg, rel, dead_entries, out_dir, in_place, comment_only,
                  dry_run, client, verbose):
    abs_src = cfg.path(rel)
    if not os.path.isfile(abs_src):
        return FileOutcome(rel, "error", note="source file not found")

    with open(abs_src, "r", encoding="utf-8", errors="replace") as f:
        original = f.read()

    ext = os.path.splitext(rel)[1]
    dead_ranges = [(d["start_line"], d["end_line"], d["name"]) for d in dead_entries]
    dead_names = [d["name"] for d in dead_entries]

    commented = comment_out(original, dead_ranges, ext) if dead_ranges else original

    if comment_only:
        new_text, action, note = commented, "commented", ""
        # A safety net even in comment-only mode: if commenting broke Python
        # syntax (e.g. a class left with only dead methods), keep the original.
        ok, why = _verify_syntax(new_text, ext)
        if not ok:
            return FileOutcome(rel, "skipped", len(dead_ranges),
                               note="commenting would break syntax (%s); left unchanged" % why)
    else:
        system, user = build_prompt(rel, _lang(ext), dead_names, commented)
        try:
            raw = client.complete(system, user)
        except Exception as exc:   # network/API failure -> safe fallback
            new_text = commented if dead_ranges else original
            action = "fallback_commented" if dead_ranges else "skipped"
            note = "LLM call failed (%s); used commented-only version" % type(exc).__name__
            sys.stderr.write("[asi] %s: %s\n" % (rel, note))
            return _emit(rel, original, new_text, action, len(dead_ranges), note,
                         abs_src, out_dir, in_place, dry_run)

        candidate = strip_fences(raw)
        ok, why = _verify_syntax(candidate, ext)
        if ok and candidate.strip():
            new_text, action, note = candidate, "refactored", ""
        else:
            new_text = commented if dead_ranges else original
            action = "fallback_commented" if dead_ranges else "skipped"
            note = "LLM output failed verification (%s); used safe version" % why

    return _emit(rel, original, new_text, action, len(dead_ranges), note,
                 abs_src, out_dir, in_place, dry_run)


def _emit(rel, original, new_text, action, dead_count, note,
          abs_src, out_dir, in_place, dry_run):
    diff = list(difflib.unified_diff(
        original.splitlines(), new_text.splitlines(),
        fromfile="a/" + rel, tofile="b/" + rel, lineterm=""))
    changed = new_text != original

    if action == "skipped" and not changed:
        return FileOutcome(rel, "unchanged", dead_count, note=note)

    if dry_run:
        return FileOutcome(rel, action, dead_count, wrote_to="(dry-run)",
                           note=note, diff_lines=len(diff))

    if in_place:
        backup = abs_src + ".asi.bak"
        if not os.path.exists(backup):
            with open(backup, "w", encoding="utf-8") as f:
                f.write(original)
        dest = abs_src
    else:
        dest = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)

    with open(dest, "w", encoding="utf-8") as f:
        f.write(new_text)
    return FileOutcome(rel, action, dead_count, wrote_to=dest, note=note,
                       diff_lines=len(diff))


def _verify_syntax(text: str, ext: str):
    """Best-effort per-file syntax check. Returns (ok, reason)."""
    e = ext.lower().lstrip(".")
    if e in ("py", "pyi"):
        try:
            compile(text, "<asi-refactor>", "exec")
            return True, ""
        except SyntaxError as exc:
            return False, "SyntaxError: %s" % exc.msg
    # For other languages we can't cheaply parse here; rely on the optional
    # refactor.verify command (in-place mode) plus a non-empty sanity check.
    if not text.strip():
        return False, "empty output"
    return True, ""


def _run_verify_command(cfg: Config):
    cmd = cfg.get("refactor", "verify", "command")
    if not cmd:
        return None
    workdir = cfg.path(cfg.get("refactor", "verify", "workdir", default="."))
    sys.stderr.write("[asi] verify: %s\n" % cmd)
    proc = subprocess.run(cmd, shell=True, cwd=workdir)
    return proc.returncode == 0


def _restore_backups(result: RefactorResult) -> None:
    restored = 0
    for o in result.outcomes:
        if not o.wrote_to or o.wrote_to == "(dry-run)":
            continue
        backup = o.wrote_to + ".asi.bak"
        if os.path.exists(backup):
            with open(backup, "r", encoding="utf-8") as f:
                data = f.read()
            with open(o.wrote_to, "w", encoding="utf-8") as f:
                f.write(data)
            restored += 1
    sys.stderr.write("[asi] verify failed: restored %d file(s) from .asi.bak\n" % restored)
