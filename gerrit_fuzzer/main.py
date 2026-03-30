"""CLI entry point for the Gerrit fuzzing harness generator."""

import logging
import os
import sys
import tempfile
from pathlib import Path

import click


# Environment variable names
ENV_GERRIT_USERNAME = "GERRIT_USERNAME"
ENV_GERRIT_PASSWORD = "GERRIT_PASSWORD"


def _get_gerrit_auth(cli_user: str | None, cli_pass: str | None) -> tuple[str, str] | None:
    """Resolve Gerrit credentials from CLI options or environment variables.

    Priority: CLI option > environment variable.
    """
    user = cli_user or os.environ.get(ENV_GERRIT_USERNAME)
    password = cli_pass or os.environ.get(ENV_GERRIT_PASSWORD)
    if user and password:
        return (user, password)
    if user and not password:
        logging.getLogger("gerrit_fuzzer").warning(
            "Gerrit username provided but password is missing. "
            "Set %s or use --gerrit-pass.", ENV_GERRIT_PASSWORD,
        )
    return None

from gerrit_fuzzer.gerrit_client import fetch_gerrit_diff
from gerrit_fuzzer.metis_analyzer import MetisAnalyzer, AnalysisResult
from gerrit_fuzzer.harness_generator import HarnessGenerator
from gerrit_fuzzer.corpus_generator import CorpusGenerator
from gerrit_fuzzer.fuzzer_runner import FuzzerRunner, FuzzConfig, generate_report, find_clang


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Gerrit diff-based fuzzing harness generator.

    Fetches the latest commit diff from a Gerrit change, analyzes it
    with ARM Metis for security vulnerabilities, then generates and
    runs LibFuzzer harnesses targeting the findings.
    """


@cli.command()
@click.argument("gerrit_url")
@click.option("-o", "--output-dir", type=click.Path(), default=None,
              help="Output directory for generated files (default: temp dir).")
@click.option("--llm-provider", default=None,
              help="LLM provider for Metis (e.g., openai, ollama).")
@click.option("--model", default=None,
              help="LLM model name for Metis analysis.")
@click.option("--no-fuzz", is_flag=True,
              help="Generate harnesses and corpus but do not run the fuzzer.")
@click.option("--fuzz-time", type=int, default=300,
              help="Maximum fuzzing time in seconds (default: 300).")
@click.option("--jobs", type=int, default=1,
              help="Number of parallel fuzzing jobs.")
@click.option("--gerrit-user", default=None,
              help="Gerrit username (default: $GERRIT_USERNAME).")
@click.option("--gerrit-pass", default=None,
              help="Gerrit HTTP password (default: $GERRIT_PASSWORD).")
@click.option("--no-verify-ssl", is_flag=True,
              help="Disable SSL certificate verification.")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output.")
def run(gerrit_url, output_dir, llm_provider, model, no_fuzz,
        fuzz_time, jobs, gerrit_user, gerrit_pass, no_verify_ssl, verbose):
    """Run the full pipeline: fetch diff -> analyze -> generate -> fuzz."""
    _setup_logging(verbose)
    logger = logging.getLogger("gerrit_fuzzer")

    # Setup output directory
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
    else:
        out = Path(tempfile.mkdtemp(prefix="gerrit_fuzzer_"))

    harness_dir = out / "harnesses"
    corpus_base = out / "corpus"
    build_dir = out / "build"
    report_path = out / "report.txt"

    click.echo(f"Output directory: {out}")

    # Resolve credentials from CLI / environment
    auth = _get_gerrit_auth(gerrit_user, gerrit_pass)

    # Step 1: Fetch Gerrit diff
    click.echo(f"\n[1/4] Fetching diff from Gerrit: {gerrit_url}")
    if auth:
        click.echo(f"  Authenticating as: {auth[0]}")
    try:
        change = fetch_gerrit_diff(
            gerrit_url, auth=auth, verify_ssl=not no_verify_ssl,
        )
    except Exception as e:
        click.secho(f"Error fetching Gerrit diff: {e}", fg="red", err=True)
        sys.exit(1)

    click.echo(f"  Project: {change.project}")
    click.echo(f"  Branch: {change.branch}")
    click.echo(f"  Subject: {change.subject}")
    click.echo(f"  Files changed: {len(change.file_diffs)}")

    source_files = [fd for fd in change.file_diffs if fd.is_source_file]
    if not source_files:
        click.secho(
            "No C/C++ source files in this change. Nothing to fuzz.",
            fg="yellow",
        )
        sys.exit(0)

    click.echo(f"  C/C++ files: {len(source_files)}")

    # Step 2: Analyze with Metis
    click.echo(f"\n[2/4] Analyzing diff with Metis...")
    analyzer = MetisAnalyzer(
        llm_provider=llm_provider, model=model,
    )
    analysis = analyzer.analyze_diff(change, work_dir=out / "metis_work")

    click.echo(f"  Total findings: {len(analysis.findings)}")
    click.echo(f"  Fuzzable findings: {len(analysis.fuzzable_findings)}")
    for f in analysis.findings:
        click.echo(f"    [{f.severity.upper()}] {f.file_path}: {f.message}")

    # Step 3: Generate harnesses and corpus
    click.echo(f"\n[3/4] Generating fuzzing harnesses and corpus...")
    harness_gen = HarnessGenerator(harness_dir)
    harnesses = harness_gen.generate(change, analysis)

    corpus_gen = CorpusGenerator(corpus_base)
    corpus_map = corpus_gen.generate(change, analysis, harnesses)

    click.echo(f"  Generated {len(harnesses)} harness(es):")
    for h in harnesses:
        click.echo(f"    - {h.name} -> {h.target_file}")

    if no_fuzz:
        click.echo(f"\n--no-fuzz specified. Harnesses written to: {harness_dir}")
        click.echo("Build and run manually:")
        click.echo(f"  cd {harness_dir}")
        click.echo(f"  make")
        click.echo(f"  ./<harness_name> {corpus_base}/corpus_<harness_name>/")
        sys.exit(0)

    # Step 4: Build and run fuzzer
    click.echo(f"\n[4/4] Building and running LibFuzzer (max {fuzz_time}s)...")
    try:
        cc, cxx = find_clang()
        click.echo(f"  Using: {cxx}")
    except FileNotFoundError as e:
        click.secho(str(e), fg="red", err=True)
        click.echo("Install clang with: scripts/setup_libfuzzer.sh")
        sys.exit(1)

    config = FuzzConfig(
        max_total_time=fuzz_time,
        jobs=jobs,
        cc=cc,
        cxx=cxx,
    )
    runner = FuzzerRunner(build_dir, config)

    binaries = runner.build_all(harnesses, harness_dir)
    if not binaries:
        click.secho("No harnesses could be built.", fg="red", err=True)
        sys.exit(1)

    click.echo(f"  Built {len(binaries)} harness(es)")

    results = runner.run_all(binaries, corpus_map)
    generate_report(results, report_path)

    # Summary
    click.echo(f"\n{'=' * 60}")
    click.echo("FUZZING COMPLETE")
    click.echo(f"{'=' * 60}")
    total_crashes = sum(len(r.crashes) for r in results)
    total_execs = sum(r.total_executions for r in results)

    if total_crashes:
        click.secho(f"  CRASHES FOUND: {total_crashes}", fg="red", bold=True)
    else:
        click.secho(f"  No crashes found.", fg="green")

    click.echo(f"  Total executions: {total_execs}")
    click.echo(f"  Report: {report_path}")
    click.echo(f"  Output: {out}")


@cli.command()
@click.argument("gerrit_url")
@click.option("-o", "--output", type=click.Path(), default="analysis.json",
              help="Output file for analysis results.")
@click.option("--gerrit-user", default=None,
              help="Gerrit username (default: $GERRIT_USERNAME).")
@click.option("--gerrit-pass", default=None,
              help="Gerrit HTTP password (default: $GERRIT_PASSWORD).")
@click.option("--no-verify-ssl", is_flag=True)
@click.option("-v", "--verbose", is_flag=True)
def analyze(gerrit_url, output, gerrit_user, gerrit_pass,
            no_verify_ssl, verbose):
    """Fetch and analyze a Gerrit change (without generating harnesses)."""
    import json
    _setup_logging(verbose)

    auth = _get_gerrit_auth(gerrit_user, gerrit_pass)
    change = fetch_gerrit_diff(gerrit_url, auth=auth,
                               verify_ssl=not no_verify_ssl)
    analyzer = MetisAnalyzer()
    result = analyzer.analyze_diff(change)

    data = {
        "change_id": change.change_id,
        "project": change.project,
        "subject": change.subject,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "message": f.message,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "cwe_id": f.cwe_id,
                "fuzzable": f.is_fuzzable,
            }
            for f in result.findings
        ],
    }
    Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
    click.echo(f"Analysis written to: {output}")


@cli.command()
@click.argument("gerrit_url")
@click.option("-o", "--output-dir", type=click.Path(), required=True,
              help="Directory for generated harness files.")
@click.option("--gerrit-user", default=None,
              help="Gerrit username (default: $GERRIT_USERNAME).")
@click.option("--gerrit-pass", default=None,
              help="Gerrit HTTP password (default: $GERRIT_PASSWORD).")
@click.option("--no-verify-ssl", is_flag=True)
@click.option("-v", "--verbose", is_flag=True)
def generate(gerrit_url, output_dir, gerrit_user, gerrit_pass,
             no_verify_ssl, verbose):
    """Generate harnesses and corpus without running the fuzzer."""
    _setup_logging(verbose)

    auth = _get_gerrit_auth(gerrit_user, gerrit_pass)
    change = fetch_gerrit_diff(gerrit_url, auth=auth,
                               verify_ssl=not no_verify_ssl)

    analyzer = MetisAnalyzer()
    analysis = analyzer.analyze_diff(change)

    out = Path(output_dir)
    harness_gen = HarnessGenerator(out / "harnesses")
    harnesses = harness_gen.generate(change, analysis)

    corpus_gen = CorpusGenerator(out / "corpus")
    corpus_gen.generate(change, analysis, harnesses)

    click.echo(f"Generated {len(harnesses)} harness(es) in {out}")


@cli.command()
@click.argument("harness_dir", type=click.Path(exists=True))
@click.option("--fuzz-time", type=int, default=300)
@click.option("--jobs", type=int, default=1)
@click.option("-v", "--verbose", is_flag=True)
def fuzz(harness_dir, fuzz_time, jobs, verbose):
    """Build and run previously generated harnesses."""
    _setup_logging(verbose)

    hdir = Path(harness_dir)
    build_dir = hdir.parent / "build"

    cc, cxx = find_clang()
    config = FuzzConfig(max_total_time=fuzz_time, jobs=jobs, cc=cc, cxx=cxx)
    runner = FuzzerRunner(build_dir, config)

    # Find harness source files
    sources = list(hdir.glob("fuzz_*.cpp"))
    if not sources:
        click.secho("No harness sources found.", fg="red", err=True)
        sys.exit(1)

    from gerrit_fuzzer.harness_generator import HarnessInfo
    harnesses = [
        HarnessInfo(name=s.stem, source=s.name, target_file="")
        for s in sources
    ]

    binaries = runner.build_all(harnesses, hdir)
    corpus_base = hdir.parent / "corpus"
    corpus_map = {
        name: corpus_base / f"corpus_{name}"
        for name in binaries
    }

    results = runner.run_all(binaries, corpus_map)
    report_path = hdir.parent / "report.txt"
    generate_report(results, report_path)
    click.echo(f"Report: {report_path}")


if __name__ == "__main__":
    cli()
