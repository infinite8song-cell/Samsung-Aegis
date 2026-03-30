"""Integration with ARM Metis for AI-driven security analysis of diffs.

Metis integration strategy (in priority order):
  1. Python API - import metis directly and call MetisEngine.review_patch()
  2. CLI subprocess - call `metis --non-interactive --command "review_patch ..."`
  3. Heuristic fallback - regex-based pattern matching for common C/C++ vulnerabilities
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from gerrit_fuzzer.gerrit_client import GerritChange, FileDiff

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """A single security finding from Metis analysis."""
    rule_id: str
    severity: str  # critical, high, medium, low, info
    message: str
    file_path: str
    start_line: int
    end_line: int
    category: str  # e.g., buffer-overflow, integer-overflow, use-after-free
    confidence: float  # 0.0 - 1.0
    snippet: str = ""
    cwe_id: str = ""

    @property
    def is_fuzzable(self) -> bool:
        """Whether this finding can be targeted by fuzzing."""
        fuzzable_categories = {
            "buffer-overflow", "heap-overflow", "stack-overflow",
            "integer-overflow", "integer-underflow",
            "format-string", "use-after-free", "double-free",
            "null-dereference", "out-of-bounds",
            "uninitialized-memory", "memory-corruption",
            "command-injection", "path-traversal",
            "type-confusion", "race-condition",
        }
        return self.category in fuzzable_categories or self.severity in {
            "critical", "high"
        }


@dataclass
class AnalysisResult:
    """Results from Metis analysis."""
    findings: list[SecurityFinding] = field(default_factory=list)
    raw_sarif: dict | None = None
    analyzed_files: list[str] = field(default_factory=list)
    analysis_method: str = ""  # "metis-api", "metis-cli", "heuristic"

    @property
    def fuzzable_findings(self) -> list[SecurityFinding]:
        return [f for f in self.findings if f.is_fuzzable]

    @property
    def source_file_findings(self) -> dict[str, list[SecurityFinding]]:
        result: dict[str, list[SecurityFinding]] = {}
        for f in self.fuzzable_findings:
            result.setdefault(f.file_path, []).append(f)
        return result


def _parse_sarif(sarif: dict) -> list[SecurityFinding]:
    """Parse SARIF format output into SecurityFinding objects."""
    findings = []
    for run in sarif.get("runs", []):
        rules = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[rule["id"]] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_info = rules.get(rule_id, {})

            severity = _map_severity(
                result.get("level", "warning"),
                rule_info,
            )
            category = _infer_category(rule_id, result.get("message", {}).get("text", ""))

            for location in result.get("locations", []):
                phys = location.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})

                findings.append(SecurityFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=result.get("message", {}).get("text", ""),
                    file_path=artifact,
                    start_line=region.get("startLine", 0),
                    end_line=region.get("endLine", region.get("startLine", 0)),
                    category=category,
                    confidence=_level_to_confidence(result.get("level", "warning")),
                    snippet=phys.get("contextRegion", {}).get("snippet", {}).get("text", ""),
                    cwe_id=_extract_cwe(rule_info),
                ))

    return findings


def _parse_metis_json(data: dict) -> list[SecurityFinding]:
    """Parse Metis native JSON output (non-SARIF) into SecurityFinding objects."""
    findings = []

    reviews = data.get("reviews", [])
    if isinstance(reviews, list):
        for review in reviews:
            file_path = review.get("file", review.get("filename", ""))
            issues = review.get("issues", review.get("findings", []))
            if isinstance(issues, str):
                # Sometimes Metis returns review text as a string
                findings.append(SecurityFinding(
                    rule_id="metis-review",
                    severity="medium",
                    message=issues,
                    file_path=file_path,
                    start_line=0,
                    end_line=0,
                    category=_infer_category("metis", issues),
                    confidence=0.7,
                ))
                continue
            for issue in (issues if isinstance(issues, list) else []):
                msg = issue if isinstance(issue, str) else issue.get(
                    "description", issue.get("message", str(issue))
                )
                line = 0 if isinstance(issue, str) else issue.get("line", 0)
                sev = "medium" if isinstance(issue, str) else issue.get(
                    "severity", "medium"
                )
                findings.append(SecurityFinding(
                    rule_id="metis-review",
                    severity=sev,
                    message=msg,
                    file_path=file_path,
                    start_line=line,
                    end_line=line,
                    category=_infer_category("metis", msg),
                    confidence=0.7,
                    snippet=issue.get("snippet", "") if isinstance(issue, dict) else "",
                ))

    # Handle "overall_changes" summary
    overall = data.get("overall_changes", "")
    if overall and not findings:
        findings.append(SecurityFinding(
            rule_id="metis-summary",
            severity="medium",
            message=overall,
            file_path="",
            start_line=0,
            end_line=0,
            category=_infer_category("metis", overall),
            confidence=0.6,
        ))

    return findings


def _map_severity(level: str, rule_info: dict) -> str:
    props = rule_info.get("properties", {})
    if "security-severity" in props:
        score = float(props["security-severity"])
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        return "low"
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "info")


def _level_to_confidence(level: str) -> float:
    return {"error": 0.9, "warning": 0.7, "note": 0.5}.get(level, 0.3)


def _infer_category(rule_id: str, message: str) -> str:
    """Infer vulnerability category from rule ID and message text."""
    text = f"{rule_id} {message}".lower()
    patterns = [
        ("buffer-overflow", ["buffer overflow", "buffer overrun", "bufferoverflow"]),
        ("heap-overflow", ["heap overflow", "heap-based"]),
        ("stack-overflow", ["stack overflow", "stack-based"]),
        ("integer-overflow", ["integer overflow", "int overflow", "arithmetic overflow"]),
        ("integer-underflow", ["integer underflow", "int underflow"]),
        ("use-after-free", ["use after free", "use-after-free", "dangling pointer"]),
        ("double-free", ["double free", "double-free"]),
        ("null-dereference", ["null pointer", "null dereference", "nullptr"]),
        ("out-of-bounds", ["out of bounds", "oob", "array index"]),
        ("format-string", ["format string", "printf"]),
        ("uninitialized-memory", ["uninitialized", "uninit"]),
        ("memory-corruption", ["memory corruption", "memory safety"]),
        ("command-injection", ["command injection", "os command"]),
        ("path-traversal", ["path traversal", "directory traversal"]),
        ("type-confusion", ["type confusion"]),
        ("race-condition", ["race condition", "toctou", "data race"]),
    ]
    for category, keywords in patterns:
        if any(kw in text for kw in keywords):
            return category
    return "general-security"


def _extract_cwe(rule_info: dict) -> str:
    for tag in rule_info.get("properties", {}).get("tags", []):
        if tag.startswith("CWE-"):
            return tag
    return ""


class MetisAnalyzer:
    """Orchestrates Metis analysis on Gerrit diffs.

    Tries three strategies in order:
      1. Python API (import metis.engine.MetisEngine)
      2. CLI subprocess (metis --non-interactive)
      3. Heuristic regex fallback
    """

    def __init__(self, llm_provider: str | None = None,
                 model: str | None = None):
        self.llm_provider = llm_provider
        self.model = model

    def analyze_diff(self, change: GerritChange,
                     work_dir: Path | None = None) -> AnalysisResult:
        """Run Metis analysis on the Gerrit diff."""
        if work_dir is None:
            tmp = tempfile.mkdtemp(prefix="gerrit_fuzzer_")
            work_dir = Path(tmp)
        work_dir.mkdir(parents=True, exist_ok=True)

        diff_file = work_dir / "change.diff"
        diff_file.write_text(change.raw_diff, encoding="utf-8")

        result = AnalysisResult(
            analyzed_files=[fd.new_path for fd in change.file_diffs],
        )

        # Strategy 1: Python API
        findings = self._try_python_api(diff_file, work_dir)
        if findings is not None:
            result.findings = findings
            result.analysis_method = "metis-api"
            logger.info("Metis Python API analysis: %d findings", len(findings))
            return result

        # Strategy 2: CLI subprocess
        findings = self._try_cli(diff_file, work_dir)
        if findings is not None:
            result.findings = findings
            result.analysis_method = "metis-cli"
            logger.info("Metis CLI analysis: %d findings", len(findings))
            return result

        # Strategy 3: Heuristic fallback
        logger.warning("Metis unavailable. Using heuristic analysis.")
        result.findings = self._heuristic_analysis(change)
        result.analysis_method = "heuristic"
        return result

    def _try_python_api(self, diff_file: Path,
                        work_dir: Path) -> list[SecurityFinding] | None:
        """Try to use Metis Python API directly."""
        try:
            from metis.configuration import load_runtime_config
            from metis.engine import MetisEngine
            from metis.providers.registry import get_provider
        except ImportError:
            logger.debug("Metis Python package not installed.")
            return None

        try:
            # Load Metis configuration (from metis.yaml or package defaults)
            runtime = load_runtime_config()

            # Override LLM provider if specified
            if self.llm_provider:
                runtime["llm_provider_name"] = self.llm_provider
            if self.model:
                runtime["model"] = self.model
                runtime["llama_query_model"] = self.model

            # Build LLM provider
            llm_provider_name = runtime.get("llm_provider_name", "openai")
            provider_cls = get_provider(llm_provider_name)
            llm_provider = provider_cls(runtime)

            # Build vector backend (ChromaDB)
            embed_model_code = llm_provider.get_embed_model_code()
            embed_model_docs = llm_provider.get_embed_model_docs()

            from metis.cli.utils import build_chroma_backend
            import argparse
            args = argparse.Namespace(chroma_dir=str(work_dir / "chromadb"))
            vector_backend = build_chroma_backend(
                args, runtime, embed_model_code, embed_model_docs,
            )

            # Create engine and run review_patch
            engine = MetisEngine(
                codebase_path=str(work_dir),
                llm_provider=llm_provider,
                vector_backend=vector_backend,
                **runtime,
            )

            logger.info("Running Metis review_patch via Python API...")
            results = engine.review_patch(patch_file=str(diff_file))

            # Parse results
            if isinstance(results, dict):
                return _parse_metis_json(results)
            return []

        except Exception as e:
            logger.warning("Metis Python API failed: %s", e)
            return None

    def _try_cli(self, diff_file: Path,
                 work_dir: Path) -> list[SecurityFinding] | None:
        """Try to run Metis via CLI subprocess."""
        import shutil
        metis_bin = shutil.which("metis")
        if not metis_bin:
            logger.debug("Metis CLI binary not found in PATH.")
            return None

        output_json = work_dir / "metis_output.json"
        output_sarif = work_dir / "metis_output.sarif"

        # Metis CLI: metis --non-interactive --command "review_patch <file>"
        #            --output-file <output> [--output-file <sarif>]
        cmd = [
            metis_bin,
            "--non-interactive",
            "--command", f"review_patch {diff_file}",
            "--output-file", str(output_json),
            "--output-file", str(output_sarif),
            "--chroma-dir", str(work_dir / "chromadb"),
            "--codebase-path", str(work_dir),
        ]

        logger.info("Running Metis CLI: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600,
                cwd=str(work_dir),
            )

            if proc.returncode != 0:
                logger.warning("Metis CLI exited with code %d: %s",
                               proc.returncode, proc.stderr[:500])

            # Try SARIF output first
            if output_sarif.exists():
                try:
                    sarif = json.loads(output_sarif.read_text())
                    if "runs" in sarif:
                        return _parse_sarif(sarif)
                except (json.JSONDecodeError, KeyError):
                    pass

            # Try JSON output
            if output_json.exists():
                try:
                    data = json.loads(output_json.read_text())
                    if "$schema" in str(data) and "runs" in data:
                        return _parse_sarif(data)
                    return _parse_metis_json(data)
                except (json.JSONDecodeError, KeyError):
                    pass

            # Try parsing stdout
            if proc.stdout.strip():
                try:
                    data = json.loads(proc.stdout)
                    return _parse_metis_json(data)
                except (json.JSONDecodeError, TypeError):
                    pass

            if proc.returncode == 0:
                return []  # Metis ran but found nothing

            return None

        except FileNotFoundError:
            logger.debug("Metis binary disappeared: %s", metis_bin)
            return None
        except subprocess.TimeoutExpired:
            logger.warning("Metis CLI timed out after 600s.")
            return None

    def _heuristic_analysis(self, change: GerritChange) -> list[SecurityFinding]:
        """Fallback: pattern-based analysis when Metis is unavailable."""
        import re
        findings = []
        dangerous_patterns = [
            (r"\bmemcpy\s*\(", "buffer-overflow",
             "Potential buffer overflow via memcpy without bounds check"),
            (r"\bstrcpy\s*\(", "buffer-overflow",
             "Potential buffer overflow via strcpy (use strncpy)"),
            (r"\bsprintf\s*\(", "buffer-overflow",
             "Potential buffer overflow via sprintf (use snprintf)"),
            (r"\bgets\s*\(", "buffer-overflow",
             "Dangerous gets() call (use fgets)"),
            (r"\bmalloc\s*\([^)]*\)\s*;(?!.*if)", "null-dereference",
             "malloc without NULL check"),
            (r"\bfree\s*\(\s*(\w+)\s*\)[\s\S]{0,50}\bfree\s*\(\s*\1\s*\)",
             "double-free", "Potential double-free"),
            (r"\bscanf\s*\(\s*\"[^\"]*%s", "buffer-overflow",
             "Unbounded scanf %s format specifier"),
            (r"\batoi\s*\(", "integer-overflow",
             "atoi without error checking (use strtol)"),
            (r"\brealloc\s*\(.*,\s*\w+\s*\*\s*\w+", "integer-overflow",
             "Potential integer overflow in realloc size calculation"),
            (r"\bstrcat\s*\(", "buffer-overflow",
             "Potential buffer overflow via strcat (use strncat)"),
        ]

        for fd in change.file_diffs:
            if not fd.is_source_file:
                continue
            for hunk in fd.hunks:
                for i, line in enumerate(hunk.lines):
                    if not line.startswith("+"):
                        continue
                    content = line[1:]
                    for pattern, category, message in dangerous_patterns:
                        if re.search(pattern, content):
                            findings.append(SecurityFinding(
                                rule_id=f"heuristic-{category}",
                                severity="medium",
                                message=message,
                                file_path=fd.new_path,
                                start_line=hunk.new_start + i,
                                end_line=hunk.new_start + i,
                                category=category,
                                confidence=0.5,
                                snippet=content.strip(),
                            ))

        return findings


def analyze_gerrit_change(change: GerritChange,
                          work_dir: Path | None = None) -> AnalysisResult:
    """Convenience function to analyze a Gerrit change."""
    analyzer = MetisAnalyzer()
    return analyzer.analyze_diff(change, work_dir=work_dir)
