"""Integration with ARM Metis for AI-driven security analysis of diffs."""

import json
import logging
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
    """Orchestrates Metis analysis on Gerrit diffs."""

    def __init__(self, metis_cmd: str = "metis",
                 llm_provider: str | None = None,
                 model: str | None = None):
        self.metis_cmd = metis_cmd
        self.llm_provider = llm_provider
        self.model = model

    def analyze_diff(self, change: GerritChange,
                     work_dir: Path | None = None) -> AnalysisResult:
        """Run Metis review_patch on the Gerrit diff."""
        if work_dir is None:
            tmp = tempfile.mkdtemp(prefix="gerrit_fuzzer_")
            work_dir = Path(tmp)

        diff_file = work_dir / "change.diff"
        diff_file.write_text(change.raw_diff, encoding="utf-8")

        sarif_file = work_dir / "findings.sarif"
        result = AnalysisResult(
            analyzed_files=[fd.new_path for fd in change.file_diffs],
        )

        cmd = [
            self.metis_cmd,
            "--non-interactive",
            "--command", "review_patch",
            str(diff_file),
            "--output", str(sarif_file),
            "--format", "sarif",
        ]
        if self.llm_provider:
            cmd.extend(["--llm-provider", self.llm_provider])
        if self.model:
            cmd.extend(["--model", self.model])

        logger.info("Running Metis: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600,
                cwd=str(work_dir),
            )
            if proc.returncode != 0:
                logger.warning("Metis exited with code %d: %s",
                               proc.returncode, proc.stderr)
                # Try to parse any partial output
                if sarif_file.exists():
                    sarif = json.loads(sarif_file.read_text())
                    result.raw_sarif = sarif
                    result.findings = _parse_sarif(sarif)
                else:
                    # Fall back to heuristic analysis
                    result.findings = self._heuristic_analysis(change)
                return result

            if sarif_file.exists():
                sarif = json.loads(sarif_file.read_text())
                result.raw_sarif = sarif
                result.findings = _parse_sarif(sarif)
            else:
                # Check stdout for JSON output
                try:
                    output = json.loads(proc.stdout)
                    if "$schema" in str(output):
                        result.raw_sarif = output
                        result.findings = _parse_sarif(output)
                except (json.JSONDecodeError, TypeError):
                    result.findings = self._heuristic_analysis(change)

        except FileNotFoundError:
            logger.warning(
                "Metis not found at '%s'. Falling back to heuristic analysis.",
                self.metis_cmd,
            )
            result.findings = self._heuristic_analysis(change)
        except subprocess.TimeoutExpired:
            logger.warning("Metis analysis timed out.")
            result.findings = self._heuristic_analysis(change)

        return result

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
                          metis_cmd: str = "metis",
                          work_dir: Path | None = None) -> AnalysisResult:
    """Convenience function to analyze a Gerrit change."""
    analyzer = MetisAnalyzer(metis_cmd=metis_cmd)
    return analyzer.analyze_diff(change, work_dir=work_dir)
