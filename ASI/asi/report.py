"""Turn a :class:`Report` into human- and machine-readable output.

Three products:
  * a terminal summary (always),
  * ``report.json`` -- the full machine-readable result, and
  * ``report.md``   -- a review-friendly dead-code report grouped by file,
                       plus an optimisation section (hottest live functions).
"""

from __future__ import annotations

import json
import os

from .model import Report


def print_summary(report: Report, stream) -> None:
    dead = report.dead
    total = len(report.functions)
    live = total - len(dead)
    stream.write("\n" + "=" * 60 + "\n")
    stream.write("ASI dead-code report: %s (backend=%s)\n" % (report.name, report.backend))
    stream.write("=" * 60 + "\n")
    stream.write("  vectors replayed : %d (%d ok, %d failed)\n"
                 % (report.run_stats.total, report.run_stats.ok, report.run_stats.failed))
    stream.write("  functions        : %d total, %d live, %d DEAD\n" % (total, live, len(dead)))
    stream.write("  dead lines (~)    : %d\n" % report.dead_loc)
    if report.run_stats.failed:
        stream.write("  ! %d vector run(s) failed -- dead results may be under-counted\n"
                     % report.run_stats.failed)
    stream.write("\n")
    if dead:
        stream.write("Dead functions (never executed by the corpus):\n")
        for f in sorted(dead, key=lambda x: (x.file, x.start_line)):
            stream.write("  %-40s %s:%d-%d\n" % (f.name, f.file, f.start_line, f.end_line))
    else:
        stream.write("No dead functions found -- every function ran at least once.\n")
    stream.write("\n")


def write_reports(report: Report, out_dir: str, formats=None) -> list:
    formats = formats or ["md", "json"]
    os.makedirs(out_dir, exist_ok=True)
    written = []
    if "json" in formats:
        p = os.path.join(out_dir, "report.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(_as_dict(report), f, indent=2)
        written.append(p)
    if "md" in formats:
        p = os.path.join(out_dir, "report.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(_as_markdown(report))
        written.append(p)
    return written


def _as_dict(report: Report) -> dict:
    return {
        "name": report.name,
        "backend": report.backend,
        "summary": {
            "vectors": report.run_stats.total,
            "vectors_ok": report.run_stats.ok,
            "vectors_failed": report.run_stats.failed,
            "functions_total": len(report.functions),
            "functions_live": len(report.live),
            "functions_dead": len(report.dead),
            "dead_loc": report.dead_loc,
        },
        "dead": [f.to_dict() for f in sorted(report.dead, key=lambda x: (x.file, x.start_line))],
        "live": [f.to_dict() for f in sorted(report.live, key=lambda x: -x.hits)],
        "failures": [
            {"vector": v, "code": rc} for (v, rc, _tail) in report.run_stats.failures
        ],
    }


def _as_markdown(report: Report) -> str:
    dead = sorted(report.dead, key=lambda x: (x.file, x.start_line))
    live = sorted(report.live, key=lambda x: -x.hits)
    lines = []
    lines.append("# ASI dead-code report: `%s`\n" % report.name)
    lines.append("- backend: `%s`" % report.backend)
    lines.append("- vectors replayed: **%d** (%d ok, %d failed)"
                 % (report.run_stats.total, report.run_stats.ok, report.run_stats.failed))
    lines.append("- functions: **%d** total / **%d** live / **%d** dead"
                 % (len(report.functions), len(report.live), len(report.dead)))
    lines.append("- dead lines of code (approx): **%d**\n" % report.dead_loc)

    if report.run_stats.failed:
        lines.append("> ⚠️ %d vector run(s) failed. A function that only runs on a failing "
                     "path may be misreported as dead. Investigate failures before deleting code.\n"
                     % report.run_stats.failed)

    lines.append("## Dead code — safe-to-remove candidates\n")
    lines.append("Functions defined in the analysed sources that **no test vector ever executed**.\n")
    if not dead:
        lines.append("_None. Every function ran at least once._\n")
    else:
        by_file = {}
        for f in dead:
            by_file.setdefault(f.file, []).append(f)
        for fpath in sorted(by_file):
            lines.append("### `%s`\n" % fpath)
            lines.append("| function | lines | ~LOC |")
            lines.append("|---|---|---|")
            for f in by_file[fpath]:
                lines.append("| `%s` | %d–%d | %d |" % (f.name, f.start_line, f.end_line, f.loc))
            lines.append("")

    lines.append("## Optimisation hotspots — hottest live functions\n")
    lines.append("Highest execution counts across the corpus: the best targets for optimisation.\n")
    hot = [f for f in live if f.hits > 0][:25]
    if not hot:
        lines.append("_No execution counts available for this backend._\n")
    else:
        lines.append("| function | file | hits |")
        lines.append("|---|---|---|")
        for f in hot:
            lines.append("| `%s` | `%s` | %d |" % (f.name, f.file, f.hits))
        lines.append("")

    return "\n".join(lines) + "\n"
