"""Command-line interface: ``python -m asi <command>``."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .backends import available
from .config import ConfigError, load_config
from .engine import analyze
from .manifest import resolve_vectors
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
