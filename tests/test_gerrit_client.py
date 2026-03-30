"""Tests for the Gerrit client module."""

import pytest
from gerrit_fuzzer.gerrit_client import parse_gerrit_url, FileDiff, _detect_language


class TestParseGerritUrl:
    def test_standard_url(self):
        result = parse_gerrit_url("https://gerrit.example.com/c/my/project/+/12345")
        assert result["base_url"] == "https://gerrit.example.com"
        assert result["change_number"] == 12345

    def test_url_with_patchset(self):
        result = parse_gerrit_url("https://gerrit.example.com/c/my/project/+/99999/3")
        assert result["change_number"] == 99999

    def test_fragment_url(self):
        result = parse_gerrit_url("https://gerrit.example.com/#/c/54321/")
        assert result["change_number"] == 54321

    def test_simple_url(self):
        result = parse_gerrit_url("https://gerrit.example.com/changes/11111")
        assert result["change_number"] == 11111

    def test_bare_url(self):
        result = parse_gerrit_url("gerrit.example.com/77777")
        assert result["base_url"] == "https://gerrit.example.com"
        assert result["change_number"] == 77777

    def test_url_with_port(self):
        result = parse_gerrit_url("https://gerrit.example.com:8080/c/proj/+/42")
        assert result["base_url"] == "https://gerrit.example.com:8080"
        assert result["change_number"] == 42

    def test_invalid_url(self):
        with pytest.raises(ValueError, match="Cannot parse"):
            parse_gerrit_url("https://gerrit.example.com/dashboard")


class TestFileDiff:
    def test_is_source_file_c(self):
        fd = FileDiff(old_path=None, new_path="src/main.c", status="ADDED")
        assert fd.is_source_file is True

    def test_is_source_file_cpp(self):
        fd = FileDiff(old_path=None, new_path="lib/parser.cpp", status="MODIFIED")
        assert fd.is_source_file is True

    def test_is_source_file_header(self):
        fd = FileDiff(old_path=None, new_path="include/api.h", status="MODIFIED")
        assert fd.is_source_file is True

    def test_is_source_file_python(self):
        fd = FileDiff(old_path=None, new_path="setup.py", status="MODIFIED")
        assert fd.is_source_file is False

    def test_is_source_file_makefile(self):
        fd = FileDiff(old_path=None, new_path="Makefile", status="MODIFIED")
        assert fd.is_source_file is False


class TestDetectLanguage:
    def test_c_file(self):
        assert _detect_language("main.c") == "c"

    def test_cpp_file(self):
        assert _detect_language("parser.cpp") == "cpp"

    def test_header(self):
        assert _detect_language("types.h") == "c"

    def test_python(self):
        assert _detect_language("script.py") == "python"

    def test_unknown(self):
        assert _detect_language("Makefile") == ""
