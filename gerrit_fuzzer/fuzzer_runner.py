"""Build and run LibFuzzer harnesses."""

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from gerrit_fuzzer.harness_generator import HarnessInfo

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    """Result of a fuzzing run."""
    harness_name: str
    crashes: list[Path] = field(default_factory=list)
    timeouts: list[Path] = field(default_factory=list)
    ooms: list[Path] = field(default_factory=list)
    total_executions: int = 0
    duration_seconds: float = 0.0
    coverage_pcs: int = 0
    return_code: int = 0
    log_file: Path | None = None

    @property
    def has_findings(self) -> bool:
        return bool(self.crashes or self.timeouts or self.ooms)


@dataclass
class FuzzConfig:
    """Configuration for a fuzzing run."""
    max_total_time: int = 300  # seconds
    max_len: int = 65536
    jobs: int = 1
    rss_limit_mb: int = 2048
    timeout: int = 30  # per-input timeout
    dict_path: Path | None = None
    extra_flags: list[str] = field(default_factory=list)
    cc: str = "clang"
    cxx: str = "clang++"
    sanitizers: list[str] = field(default_factory=lambda: ["fuzzer", "address", "undefined"])
    opt_level: str = "-O1"
    debug: bool = True


def find_clang() -> tuple[str, str]:
    """Find clang/clang++ in PATH or common locations."""
    for suffix in ["", "-17", "-16", "-15", "-14", "-13"]:
        cc = f"clang{suffix}"
        cxx = f"clang++{suffix}"
        if shutil.which(cc) and shutil.which(cxx):
            return cc, cxx

    # Check common install locations
    for base in ["/usr/lib/llvm", "/usr/local/lib/llvm"]:
        for ver in range(17, 12, -1):
            cc = f"{base}-{ver}/bin/clang"
            cxx = f"{base}-{ver}/bin/clang++"
            if os.path.isfile(cc) and os.path.isfile(cxx):
                return cc, cxx

    raise FileNotFoundError(
        "clang/clang++ not found. Install with: "
        "apt install clang or run scripts/setup_libfuzzer.sh"
    )


class FuzzerRunner:
    """Builds and runs LibFuzzer harnesses."""

    def __init__(self, build_dir: Path, config: FuzzConfig | None = None):
        self.build_dir = build_dir
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or FuzzConfig()

    def build_harness(self, harness: HarnessInfo,
                      harness_dir: Path,
                      source_dirs: list[Path] | None = None) -> Path:
        """Compile a single harness with LibFuzzer instrumentation.

        Returns path to the compiled binary.
        """
        source_path = harness_dir / harness.source
        if not source_path.exists():
            raise FileNotFoundError(f"Harness source not found: {source_path}")

        output_path = self.build_dir / harness.name

        sanitizer_flag = "-fsanitize=" + ",".join(self.config.sanitizers)
        cmd = [
            self.config.cxx,
            sanitizer_flag,
            "-fno-omit-frame-pointer",
            self.config.opt_level,
        ]

        if self.config.debug:
            cmd.append("-g")

        # Add include directories
        if source_dirs:
            for d in source_dirs:
                cmd.extend(["-I", str(d)])

        # Add dependency source files
        dep_files = []
        for dep in harness.dependencies:
            dep_path = harness_dir / dep
            if dep_path.exists():
                dep_files.append(str(dep_path))

        cmd.extend([
            str(source_path),
            *dep_files,
            "-o", str(output_path),
            "-lstdc++",
        ])

        for lib in harness.link_libs:
            cmd.append(f"-l{lib}")

        logger.info("Building harness: %s", " ".join(cmd))

        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )

        if proc.returncode != 0:
            logger.error("Build failed for %s:\n%s", harness.name, proc.stderr)
            raise RuntimeError(
                f"Failed to build harness {harness.name}:\n{proc.stderr}"
            )

        output_path.chmod(0o755)
        logger.info("Built harness: %s", output_path)
        return output_path

    def build_all(self, harnesses: list[HarnessInfo],
                  harness_dir: Path,
                  source_dirs: list[Path] | None = None) -> dict[str, Path]:
        """Build all harnesses. Returns mapping of name -> binary path."""
        binaries = {}
        for harness in harnesses:
            try:
                binary = self.build_harness(harness, harness_dir, source_dirs)
                binaries[harness.name] = binary
            except (RuntimeError, FileNotFoundError) as e:
                logger.warning("Skipping harness %s: %s", harness.name, e)
        return binaries

    def run_fuzzer(self, binary: Path, corpus_dir: Path,
                   artifacts_dir: Path | None = None) -> FuzzResult:
        """Run LibFuzzer on a compiled harness binary."""
        if not binary.exists():
            raise FileNotFoundError(f"Binary not found: {binary}")

        corpus_dir.mkdir(parents=True, exist_ok=True)
        if artifacts_dir is None:
            artifacts_dir = binary.parent / f"artifacts_{binary.name}"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        log_file = binary.parent / f"{binary.name}.log"

        cmd = [
            str(binary),
            str(corpus_dir),
            f"-max_total_time={self.config.max_total_time}",
            f"-max_len={self.config.max_len}",
            f"-rss_limit_mb={self.config.rss_limit_mb}",
            f"-timeout={self.config.timeout}",
            f"-jobs={self.config.jobs}",
            f"-artifact_prefix={artifacts_dir}/",
            f"-print_final_stats=1",
        ]

        if self.config.dict_path and self.config.dict_path.exists():
            cmd.append(f"-dict={self.config.dict_path}")

        cmd.extend(self.config.extra_flags)

        logger.info("Running fuzzer: %s", " ".join(cmd))

        start_time = time.monotonic()
        with open(log_file, "w") as lf:
            proc = subprocess.run(
                cmd,
                stdout=lf,
                stderr=subprocess.STDOUT,
                timeout=self.config.max_total_time + 60,
            )
        elapsed = time.monotonic() - start_time

        result = FuzzResult(
            harness_name=binary.name,
            return_code=proc.returncode,
            duration_seconds=elapsed,
            log_file=log_file,
        )

        # Collect crash artifacts
        for artifact in artifacts_dir.iterdir():
            name = artifact.name.lower()
            if "crash-" in name:
                result.crashes.append(artifact)
            elif "timeout-" in name:
                result.timeouts.append(artifact)
            elif "oom-" in name:
                result.ooms.append(artifact)

        # Parse stats from log
        result.total_executions, result.coverage_pcs = self._parse_log(log_file)

        return result

    def run_all(self, binaries: dict[str, Path],
                corpus_map: dict[str, Path]) -> list[FuzzResult]:
        """Run fuzzer on all built harnesses."""
        results = []
        for name, binary in binaries.items():
            corpus_dir = corpus_map.get(name, binary.parent / f"corpus_{name}")
            try:
                result = self.run_fuzzer(binary, corpus_dir)
                results.append(result)
                if result.has_findings:
                    logger.warning(
                        "Fuzzer %s found issues: %d crashes, %d timeouts, %d OOMs",
                        name, len(result.crashes), len(result.timeouts),
                        len(result.ooms),
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.warning("Fuzzer run failed for %s: %s", name, e)
        return results

    @staticmethod
    def _parse_log(log_file: Path) -> tuple[int, int]:
        """Parse LibFuzzer log for execution count and coverage."""
        executions = 0
        coverage = 0
        try:
            text = log_file.read_text(errors="replace")
            for line in text.splitlines():
                if "stat::number_of_executed_inputs:" in line:
                    executions = int(line.split(":")[-1].strip())
                elif "stat::peak_rss_mb:" in line:
                    pass
                elif "cov:" in line:
                    parts = line.split("cov:")
                    if len(parts) > 1:
                        try:
                            coverage = int(parts[1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
        except OSError:
            pass
        return executions, coverage


def generate_report(results: list[FuzzResult], output_path: Path) -> None:
    """Generate a summary report of all fuzzing results."""
    lines = [
        "=" * 70,
        "GERRIT FUZZER - RESULTS REPORT",
        "=" * 70,
        "",
    ]

    total_crashes = 0
    total_timeouts = 0
    total_execs = 0

    for r in results:
        total_crashes += len(r.crashes)
        total_timeouts += len(r.timeouts)
        total_execs += r.total_executions

        status = "CRASH FOUND" if r.has_findings else "CLEAN"
        lines.append(f"[{status}] {r.harness_name}")
        lines.append(f"  Duration: {r.duration_seconds:.1f}s")
        lines.append(f"  Executions: {r.total_executions}")
        lines.append(f"  Coverage PCs: {r.coverage_pcs}")
        if r.crashes:
            lines.append(f"  Crashes: {len(r.crashes)}")
            for c in r.crashes:
                lines.append(f"    - {c}")
        if r.timeouts:
            lines.append(f"  Timeouts: {len(r.timeouts)}")
        if r.ooms:
            lines.append(f"  OOMs: {len(r.ooms)}")
        lines.append("")

    lines.extend([
        "-" * 70,
        f"Total harnesses: {len(results)}",
        f"Total executions: {total_execs}",
        f"Total crashes: {total_crashes}",
        f"Total timeouts: {total_timeouts}",
        "=" * 70,
    ])

    report = "\n".join(lines)
    output_path.write_text(report, encoding="utf-8")
    logger.info("Report written to: %s", output_path)
