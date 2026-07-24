"""Command-line interface: ``python -m asi <command>``."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .backends import available
from .config import ConfigError, load_config
from .engine import analyze
from .manifest import resolve_vectors
from .refactor import refactor as run_refactor
from .report import print_summary, write_reports


def _cmd_run(args) -> int:
    cfg = load_config(args.config)
    report = analyze(cfg, verbose=args.verbose, skip_build=args.no_build)

    out_dir = args.out or cfg.path(cfg.get("report", "dir", default="asi_report"))
    formats = cfg.get("report", "formats", default=["md", "json"])
    written = write_reports(report, out_dir, formats)

    print_summary(report, sys.stdout)
    sys.stdout.write("Reports written:\n")
    for p in written:
        sys.stdout.write("  %s\n" % p)

    if args.fail_on_dead and report.dead:
        sys.stderr.write("\n[asi] exiting non-zero: %d dead function(s) found\n" % len(report.dead))
        return 1
    return 0


def _cmd_list_vectors(args) -> int:
    cfg = load_config(args.config)
    vectors = resolve_vectors(cfg)
    for v in vectors:
        sys.stdout.write(v + "\n")
    sys.stderr.write("[asi] %d vector(s)\n" % len(vectors))
    return 0


def _cmd_refactor(args) -> int:
    cfg = load_config(args.config)
    report_path = args.report or os.path.join(
        cfg.path(cfg.get("report", "dir", default="asi_report")), "report.json")
    if not os.path.isfile(report_path):
        sys.stderr.write(
            "[asi] report not found: %s\n[asi] run `asi run -c %s` first, "
            "or pass --report\n" % (report_path, args.config))
        return 2

    scope = "all" if args.all_files else cfg.get("refactor", "scope", default="dead_files")
    out_dir = args.out or cfg.path(cfg.get("refactor", "out", default="asi_refactored"))

    result = run_refactor(
        cfg, report_path=report_path, out_dir=out_dir,
        in_place=args.in_place, comment_only=args.comment_only,
        dry_run=args.dry_run, scope=scope, verbose=args.verbose)

    _print_refactor_summary(result)
    return 0


def _print_refactor_summary(result) -> None:
    mode = "comment-only" if result.comment_only else "LLM refactor"
    where = "in place (.asi.bak backups)" if result.in_place else result.out_dir
    if result_is_dry(result):
        where = "dry-run (nothing written)"
    sys.stdout.write("\n" + "=" * 60 + "\n")
    sys.stdout.write("ASI refactor (%s)\n" % mode)
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write("  output: %s\n\n" % where)
    for o in result.outcomes:
        line = "  %-22s %-20s dead=%d" % (o.file, o.action, o.dead_count)
        if o.diff_lines:
            line += " (+/- %d diff lines)" % o.diff_lines
        sys.stdout.write(line + "\n")
        if o.note:
            sys.stdout.write("        note: %s\n" % o.note)
    if result.verify_ok is True:
        sys.stdout.write("\n  verify command: PASSED\n")
    elif result.verify_ok is False:
        sys.stdout.write("\n  verify command: FAILED — files restored from .asi.bak\n")


def result_is_dry(result) -> bool:
    return any(o.wrote_to == "(dry-run)" for o in result.outcomes)


def _cmd_backends(_args) -> int:
    sys.stdout.write("Available backends:\n")
    for b in available():
        sys.stdout.write("  %s\n" % b)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asi",
        description="Find dead code by replaying test vectors and measuring "
                    "which functions actually run.",
    )
    p.add_argument("--version", action="version", version="asi %s" % __version__)
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="build, replay the corpus, and report dead code")
    run.add_argument("-c", "--config", required=True, help="path to asi config (JSON)")
    run.add_argument("-o", "--out", help="output directory for reports")
    run.add_argument("--no-build", action="store_true", help="skip the build/instrument step")
    run.add_argument("--fail-on-dead", action="store_true",
                     help="exit non-zero if any dead function is found (for CI gates)")
    run.add_argument("-v", "--verbose", action="store_true")
    run.set_defaults(func=_cmd_run)

    lv = sub.add_parser("list-vectors", help="print the resolved test-vector paths and exit")
    lv.add_argument("-c", "--config", required=True)
    lv.set_defaults(func=_cmd_list_vectors)

    rf = sub.add_parser(
        "refactor",
        help="comment out dead functions and LLM-refactor the code (uses the report)")
    rf.add_argument("-c", "--config", required=True)
    rf.add_argument("--report", help="path to report.json (default: from config's report.dir)")
    rf.add_argument("-o", "--out", help="output directory for refactored files")
    rf.add_argument("--in-place", action="store_true",
                    help="overwrite the originals (a .asi.bak backup is kept)")
    rf.add_argument("--comment-only", action="store_true",
                    help="only comment out dead functions; skip the LLM step (no API key needed)")
    rf.add_argument("--all-files", action="store_true",
                    help="refactor every analysed source file, not just those with dead code")
    rf.add_argument("--dry-run", action="store_true",
                    help="show what would change without writing")
    rf.add_argument("-v", "--verbose", action="store_true")
    rf.set_defaults(func=_cmd_refactor)

    be = sub.add_parser("backends", help="list available language backends")
    be.set_defaults(func=_cmd_backends)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, RuntimeError, ValueError) as exc:
        sys.stderr.write("[asi] error: %s\n" % exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
