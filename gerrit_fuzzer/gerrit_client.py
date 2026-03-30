"""Gerrit REST API client for fetching commit diffs."""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests


@dataclass
class DiffHunk:
    """A single hunk from a unified diff."""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str]


@dataclass
class FileDiff:
    """Diff information for a single file."""
    old_path: str | None
    new_path: str
    status: str  # ADDED, MODIFIED, DELETED, RENAMED
    hunks: list[DiffHunk] = field(default_factory=list)
    language: str = ""

    @property
    def is_source_file(self) -> bool:
        ext = Path(self.new_path).suffix.lower()
        return ext in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"}


@dataclass
class GerritChange:
    """Represents a Gerrit change with its diff."""
    change_id: str
    project: str
    branch: str
    subject: str
    commit_sha: str
    file_diffs: list[FileDiff] = field(default_factory=list)
    raw_diff: str = ""


def _detect_language(path: str) -> str:
    ext_map = {
        ".c": "c", ".h": "c",
        ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
        ".hpp": "cpp", ".hxx": "cpp",
        ".py": "python", ".rs": "rust", ".go": "go",
        ".ts": "typescript", ".js": "javascript",
    }
    return ext_map.get(Path(path).suffix.lower(), "")


def parse_gerrit_url(url: str) -> dict:
    """Parse a Gerrit URL to extract base URL and change number.

    Supports formats:
      - https://gerrit.example.com/c/project/+/12345
      - https://gerrit.example.com/#/c/12345/
      - https://gerrit.example.com/changes/12345
      - gerrit.example.com/12345
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    base = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        base += f":{parsed.port}"

    path = parsed.path.rstrip("/")
    fragment = (parsed.fragment or "").strip("/")

    # /c/project/+/12345 or /c/project/+/12345/patchset
    m = re.search(r"/c/.+/\+/(\d+)", path)
    if m:
        return {"base_url": base, "change_number": int(m.group(1))}

    # #/c/12345/
    m = re.search(r"c/(\d+)", fragment)
    if m:
        return {"base_url": base, "change_number": int(m.group(1))}

    # /changes/12345 or just /12345
    m = re.search(r"/(\d+)$", path)
    if m:
        return {"base_url": base, "change_number": int(m.group(1))}

    raise ValueError(f"Cannot parse Gerrit change number from URL: {url}")


def _strip_gerrit_prefix(text: str) -> str:
    """Strip Gerrit's XSSI prevention prefix )]}' from JSON responses."""
    if text.startswith(")]}'"):
        text = text[4:].lstrip()
    return text


class GerritClient:
    """Client for interacting with Gerrit REST API."""

    def __init__(self, base_url: str, auth: tuple[str, str] | None = None,
                 verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        if auth:
            self.session.auth = auth
        self.session.verify = verify_ssl
        self.session.headers.update({"Accept": "application/json"})

    def _get(self, endpoint: str) -> dict | list:
        url = f"{self.base_url}/a{endpoint}" if self.session.auth else \
              f"{self.base_url}{endpoint}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return json.loads(_strip_gerrit_prefix(resp.text))

    def _get_text(self, endpoint: str) -> str:
        url = f"{self.base_url}/a{endpoint}" if self.session.auth else \
              f"{self.base_url}{endpoint}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.text

    def get_change_detail(self, change_number: int) -> dict:
        return self._get(f"/changes/{change_number}/detail")

    def get_latest_revision(self, change_number: int) -> str:
        detail = self.get_change_detail(change_number)
        return detail["current_revision"]

    def get_change_diff(self, change_number: int) -> GerritChange:
        """Fetch the full diff for the latest patchset of a change."""
        detail = self.get_change_detail(change_number)
        revision = detail["current_revision"]
        rev_info = detail["revisions"][revision]

        change = GerritChange(
            change_id=detail["change_id"],
            project=detail["project"],
            branch=detail["branch"],
            subject=detail["subject"],
            commit_sha=revision,
        )

        # Get list of files changed
        files = self._get(
            f"/changes/{change_number}/revisions/{revision}/files"
        )

        for filepath, file_info in files.items():
            if filepath == "/COMMIT_MSG":
                continue

            status_map = {"A": "ADDED", "D": "DELETED", "R": "RENAMED"}
            status = status_map.get(file_info.get("status", ""), "MODIFIED")

            diff = FileDiff(
                old_path=file_info.get("old_path"),
                new_path=filepath,
                status=status,
                language=_detect_language(filepath),
            )

            # Fetch per-file diff content
            try:
                file_diff_data = self._get(
                    f"/changes/{change_number}/revisions/{revision}"
                    f"/files/{requests.utils.quote(filepath, safe='')}/diff"
                )
                for hunk_data in file_diff_data.get("content", []):
                    hunk_lines = []
                    for line in hunk_data.get("ab", []):
                        hunk_lines.append(f" {line}")
                    for line in hunk_data.get("b", []):
                        hunk_lines.append(f"+{line}")
                    for line in hunk_data.get("a", []):
                        hunk_lines.append(f"-{line}")
                    if hunk_lines:
                        diff.hunks.append(DiffHunk(
                            old_start=0, old_count=0,
                            new_start=0, new_count=0,
                            lines=hunk_lines,
                        ))
            except requests.HTTPError:
                pass

            change.file_diffs.append(diff)

        # Also fetch the unified patch for Metis
        try:
            patch_resp = self._get_text(
                f"/changes/{change_number}/revisions/{revision}/patch"
            )
            import base64
            change.raw_diff = base64.b64decode(
                _strip_gerrit_prefix(patch_resp)
            ).decode("utf-8", errors="replace")
        except Exception:
            change.raw_diff = self._generate_unified_diff(change)

        return change

    def _generate_unified_diff(self, change: GerritChange) -> str:
        """Generate unified diff text from parsed file diffs."""
        lines = []
        for fd in change.file_diffs:
            old = fd.old_path or fd.new_path
            lines.append(f"--- a/{old}")
            lines.append(f"+++ b/{fd.new_path}")
            for hunk in fd.hunks:
                lines.append(f"@@ -0,0 +0,0 @@")
                lines.extend(hunk.lines)
        return "\n".join(lines)


def fetch_gerrit_diff(gerrit_url: str, auth: tuple[str, str] | None = None,
                      verify_ssl: bool = True) -> GerritChange:
    """High-level function: parse URL and fetch the diff."""
    parsed = parse_gerrit_url(gerrit_url)
    client = GerritClient(parsed["base_url"], auth=auth, verify_ssl=verify_ssl)
    return client.get_change_diff(parsed["change_number"])
