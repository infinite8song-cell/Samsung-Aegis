"""Data model shared across the engine, backends and reporter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FunctionCoverage:
    """Aggregate coverage for a single function across *all* test vectors.

    ``hits`` is the total number of times the function was entered while the
    whole test-vector corpus was replayed. ``hits == 0`` is the definition of
    dead code used by this tool: the function exists in the source but no
    test-vector input ever caused it to run.
    """

    file: str            # source path, relative to project root when possible
    name: str            # function name (qualified: Class.method / outer.inner)
    start_line: int
    end_line: int
    hits: int            # total executions across the corpus (0 => dead)
    demangled: Optional[str] = None   # human-readable name for mangled symbols

    @property
    def dead(self) -> bool:
        return self.hits == 0

    @property
    def loc(self) -> int:
        return max(1, self.end_line - self.start_line + 1)

    def key(self) -> tuple:
        return (self.file, self.name, self.start_line)

    def to_dict(self) -> dict:
        d = {
            "file": self.file,
            "name": self.name,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "hits": self.hits,
            "dead": self.dead,
            "loc": self.loc,
        }
        if self.demangled and self.demangled != self.name:
            d["demangled"] = self.demangled
        return d


@dataclass
class RunStats:
    """Bookkeeping for how the test-vector corpus was replayed."""

    total: int = 0
    ok: int = 0
    failed: int = 0
    failures: list = field(default_factory=list)   # (vector, returncode, tail)


@dataclass
class Report:
    """Full analysis result."""

    name: str
    backend: str
    functions: list          # list[FunctionCoverage]
    run_stats: RunStats
    vectors: list = field(default_factory=list)

    @property
    def dead(self) -> list:
        return [f for f in self.functions if f.dead]

    @property
    def live(self) -> list:
        return [f for f in self.functions if not f.dead]

    @property
    def dead_loc(self) -> int:
        return sum(f.loc for f in self.dead)
