"""C / C++ backend using gcc/g++ + gcov.

Requires the target to be built with ``--coverage`` (``-fprofile-arcs
-ftest-coverage``). gcov's ``.gcda`` counters accumulate across every run, so
after the whole corpus has been replayed a single ``gcov --json-format`` pass
yields the aggregate per-function execution count. ``execution_count == 0`` is
dead code.

Relevant config block::

    "backend": "gcov",
    "build":  { "command": "make coverage", "workdir": "." },
    "gcov":   { "objdir": "build", "tool": "gcov" },
    "sources": { "include": ["src/**/*.c"], "exclude": ["**/test/**"] }
"""

from __future__ import annotations

import json
import os

from .base import Backend
from ..model import FunctionCoverage
from ..sources import resolve_sources, rel_to_root


class GcovBackend(Backend):
    key = "gcov"

    def _objdir(self) -> str:
        objdir = self.cfg.get("gcov", "objdir")
        if objdir:
            return self.cfg.path(objdir)
        return self.cfg.path(self.cfg.get("build", "workdir", default="."))

    def prepare(self) -> None:
        self._build()

    def before_run(self) -> None:
        # Discard counters from a previous analysis so hits reflect *this* corpus.
        objdir = self._objdir()
        removed = 0
        for dirpath, _dirs, files in os.walk(objdir):
            for name in files:
                if name.endswith(".gcda"):
                    try:
                        os.remove(os.path.join(dirpath, name))
                        removed += 1
                    except OSError:
                        pass

    def collect(self) -> list:
        tool = self.cfg.get("gcov", "tool", default="gcov")
        objdir = self._objdir()
        sources = resolve_sources(self.cfg)
        if not sources:
            raise RuntimeError("gcov backend: sources.include matched no files")

        agg = {}  # (file, name, start) -> FunctionCoverage
        for src in sources:
            data = self._gcov_json(tool, objdir, src)
            if not data:
                continue
            for file_entry in data.get("files", []):
                fpath = file_entry.get("file", "")
                fabs = os.path.abspath(os.path.join(objdir, fpath)) if not os.path.isabs(fpath) else fpath
                rel = rel_to_root(self.cfg, fabs)
                for fn in file_entry.get("functions", []):
                    name = fn.get("name", "?")
                    start = int(fn.get("start_line", 0))
                    end = int(fn.get("end_line", start))
                    hits = int(fn.get("execution_count", 0))
                    key = (rel, name, start)
                    existing = agg.get(key)
                    if existing is None:
                        agg[key] = FunctionCoverage(
                            file=rel, name=name, start_line=start,
                            end_line=end, hits=hits,
                            demangled=fn.get("demangled_name"),
                        )
                    else:
                        # Same inline/header function seen via multiple TUs:
                        # OR liveness by keeping the max observed count.
                        existing.hits = max(existing.hits, hits)

        return list(agg.values())

    def _gcov_json(self, tool: str, objdir: str, source: str):
        # gcov prints one JSON document describing the given translation unit.
        try:
            out = self._sh(
                [tool, "--json-format", "--stdout", "-o", objdir, source],
                cwd=objdir,
            )
        except RuntimeError:
            return None
        out = out.strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            # Some gcov builds emit gzipped intermediate files instead; those
            # setups need `gcov.tool` pointed at a wrapper. Skip gracefully.
            return None
