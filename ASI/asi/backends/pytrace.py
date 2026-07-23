"""Python backend using a pure-stdlib runtime tracer (no coverage.py needed).

Each vector runs the target script under ``asi._tracerun``, which records every
function entry. The union across all vectors is the set of *live* functions;
every function defined in ``sources.include`` but absent from that set is dead.

Relevant config block::

    "backend": "pytrace",
    "sources": { "include": ["mypkg/**/*.py"], "exclude": ["**/tests/**"] },
    "run": { "command": "solve.py {input}" }

Note: for this backend ``run.command`` must be the *target script itself*
(``script.py [args]``), NOT ``python script.py`` -- the tracer supplies the
interpreter.
"""

from __future__ import annotations

import glob
import json
import os
import shlex
import sys

from .base import Backend
from ..model import FunctionCoverage
from ..sources import resolve_sources, rel_to_root
from ..pyfuncs import enumerate_functions


class PyTraceBackend(Backend):
    key = "pytrace"

    def _tracedir(self) -> str:
        d = os.path.join(self.ctx.tmp_dir, "traces")
        os.makedirs(d, exist_ok=True)
        return d

    def prepare(self) -> None:
        # Optional build step (e.g. codegen) if the project needs one.
        self._build()

    def before_run(self) -> None:
        for p in glob.glob(os.path.join(self._tracedir(), "*.json")):
            try:
                os.remove(p)
            except OSError:
                pass

    def per_run_env(self, index: int, vector) -> dict:
        # Ensure `-m asi._tracerun` resolves regardless of the target's cwd.
        pkg_parent = self.ctx.asi_pkg_dir
        existing = os.environ.get("PYTHONPATH", "")
        pythonpath = pkg_parent + (os.pathsep + existing if existing else "")
        return {"PYTHONPATH": pythonpath}

    def wrap_command(self, command: str, index: int, vector) -> str:
        trace_out = os.path.join(self._tracedir(), "trace_%06d.json" % index)
        python = self.cfg.get("pytrace", "python", default=sys.executable)
        return "%s -m asi._tracerun --out %s --root %s -- %s" % (
            shlex.quote(python),
            shlex.quote(trace_out),
            shlex.quote(self.cfg.root),
            command,
        )

    def collect(self) -> list:
        # 1. Union of executed (file, firstlineno) across every trace file.
        executed = {}  # (abs_file, firstlineno) -> total calls
        for tf in glob.glob(os.path.join(self._tracedir(), "*.json")):
            try:
                with open(tf, "r", encoding="utf-8") as f:
                    counts = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            for key, n in counts.items():
                fn, line, _name = key.rsplit("::", 2)
                k = (os.path.abspath(fn), int(line))
                executed[k] = executed.get(k, 0) + int(n)

        # 2. Enumerate every defined function; a function is live iff its
        #    (file, start_line) appears in `executed`.
        sources = resolve_sources(self.cfg)
        if not sources:
            raise RuntimeError("pytrace backend: sources.include matched no files")

        results = []
        for src in sources:
            src_abs = os.path.abspath(src)
            rel = rel_to_root(self.cfg, src_abs)
            for qual, start, end in enumerate_functions(src_abs):
                hits = executed.get((src_abs, start), 0)
                results.append(FunctionCoverage(
                    file=rel, name=qual, start_line=start, end_line=end, hits=hits,
                ))
        return results
