"""Tests for the Metis analyzer module."""

import pytest
from gerrit_fuzzer.metis_analyzer import (
    SecurityFinding, _infer_category, _parse_sarif, MetisAnalyzer,
)
from gerrit_fuzzer.gerrit_client import GerritChange, FileDiff, DiffHunk


class TestSecurityFinding:
    def test_fuzzable_by_category(self):
        f = SecurityFinding(
            rule_id="test", severity="medium", message="test",
            file_path="a.c", start_line=1, end_line=1,
            category="buffer-overflow", confidence=0.8,
        )
        assert f.is_fuzzable is True

    def test_fuzzable_by_severity(self):
        f = SecurityFinding(
            rule_id="test", severity="critical", message="test",
            file_path="a.c", start_line=1, end_line=1,
            category="some-other-thing", confidence=0.8,
        )
        assert f.is_fuzzable is True

    def test_not_fuzzable(self):
        f = SecurityFinding(
            rule_id="test", severity="low", message="test",
            file_path="a.c", start_line=1, end_line=1,
            category="general-security", confidence=0.3,
        )
        assert f.is_fuzzable is False


class TestInferCategory:
    def test_buffer_overflow(self):
        assert _infer_category("rule1", "potential buffer overflow") == "buffer-overflow"

    def test_use_after_free(self):
        assert _infer_category("uaf", "use after free detected") == "use-after-free"

    def test_integer_overflow(self):
        assert _infer_category("x", "integer overflow in calc") == "integer-overflow"

    def test_null_dereference(self):
        assert _infer_category("np", "null pointer dereference") == "null-dereference"

    def test_generic(self):
        assert _infer_category("misc", "something weird") == "general-security"


class TestHeuristicAnalysis:
    def test_detects_strcpy(self):
        change = GerritChange(
            change_id="I123", project="test", branch="main",
            subject="test", commit_sha="abc",
            file_diffs=[
                FileDiff(
                    old_path="test.c", new_path="test.c", status="MODIFIED",
                    language="c",
                    hunks=[DiffHunk(
                        old_start=1, old_count=1, new_start=1, new_count=2,
                        lines=["+    strcpy(dst, src);"],
                    )],
                ),
            ],
        )
        analyzer = MetisAnalyzer(metis_cmd="/nonexistent")
        result = analyzer.analyze_diff(change)
        assert len(result.findings) > 0
        assert result.findings[0].category == "buffer-overflow"

    def test_detects_sprintf(self):
        change = GerritChange(
            change_id="I456", project="test", branch="main",
            subject="test", commit_sha="def",
            file_diffs=[
                FileDiff(
                    old_path="fmt.c", new_path="fmt.c", status="MODIFIED",
                    language="c",
                    hunks=[DiffHunk(
                        old_start=10, old_count=1, new_start=10, new_count=2,
                        lines=["+    sprintf(buf, \"value=%s\", input);"],
                    )],
                ),
            ],
        )
        analyzer = MetisAnalyzer(metis_cmd="/nonexistent")
        result = analyzer.analyze_diff(change)
        assert any(f.category == "buffer-overflow" for f in result.findings)

    def test_ignores_non_source_files(self):
        change = GerritChange(
            change_id="I789", project="test", branch="main",
            subject="test", commit_sha="ghi",
            file_diffs=[
                FileDiff(
                    old_path="readme.md", new_path="readme.md",
                    status="MODIFIED", language="",
                    hunks=[DiffHunk(
                        old_start=1, old_count=1, new_start=1, new_count=2,
                        lines=["+strcpy is dangerous"],
                    )],
                ),
            ],
        )
        analyzer = MetisAnalyzer(metis_cmd="/nonexistent")
        result = analyzer.analyze_diff(change)
        assert len(result.findings) == 0


class TestParseSarif:
    def test_parse_basic_sarif(self):
        sarif = {
            "runs": [{
                "tool": {
                    "driver": {
                        "rules": [{
                            "id": "BOF001",
                            "properties": {"security-severity": "8.0"},
                        }],
                    },
                },
                "results": [{
                    "ruleId": "BOF001",
                    "level": "error",
                    "message": {"text": "buffer overflow in memcpy"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/main.c"},
                            "region": {"startLine": 42, "endLine": 42},
                        },
                    }],
                }],
            }],
        }
        findings = _parse_sarif(sarif)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].file_path == "src/main.c"
        assert findings[0].start_line == 42

    def test_parse_empty_sarif(self):
        assert _parse_sarif({"runs": []}) == []
        assert _parse_sarif({}) == []
