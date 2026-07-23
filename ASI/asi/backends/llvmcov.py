"""C / C++ backend using clang + llvm-cov (source-based coverage).

Requires the target to be built with
``-fprofile-instr-generate -fcoverage-mapping``. Each run writes its own
``.profraw`` (via the per-run ``LLVM_PROFILE_FILE`` env var); they are merged
with ``llvm-profdata`` and exported with ``llvm-cov export``. A function whose
exported ``count`` is 0 was never executed.

Relevant config block::

    "backend": "llvmcov",
    "build":   { "command": "make clang-cov", "workdir": "." },
    "llvmcov": {
        "binary": "build/prog",
        "profdata_tool": "llvm-profdata",
        "cov_tool": "llvm-cov"
    }
"""

from __future__ import annotations

import glob
import json
import os

from .base import Backend
from ..model import FunctionCoverage
from ..sources import rel_to_root


class LlvmCovBackend(Backend):
    key = "llvmcov"

    def _profdir(self) -> str:
        d = os.path.join(self.ctx.tmp_dir, "profraw")
        os.makedirs(d, exist_ok=True)
        return d

    def prepare(self) -> None:
        self._build()

    def before_run(self) -> None:
        for p in glob.glob(os.path.join(self._profdir(), "*.profraw")):
            try:
                os.remove(p)
            except OSError:
                pass

    def per_run_env(self, index: int, vector) -> dict:
        return {"LLVM_PROFILE_FILE": os.path.join(self._profdir(), "vec_%06d.profraw" % index)}

    def collect(self) -> list:
        profdata_tool = self.cfg.get("llvmcov", "profdata_tool", default="llvm-profdata")
        cov_tool = self.cfg.get("llvmcov", "cov_tool", default="llvm-cov")
        binary = self.cfg.path(self.cfg.require("llvmcov", "binary"))

        profraws = sorted(glob.glob(os.path.join(self._profdir(), "*.profraw")))
        if not profraws:
            raise RuntimeError("llvmcov backend: no .profraw produced; did the runs write coverage?")

        merged = os.path.join(self.ctx.tmp_dir, "merged.profdata")
        self._sh([profdata_tool, "merge", "-sparse", *profraws, "-o", merged])

        out = self._sh([cov_tool, "export", "-instr-profile", merged,
                        binary, "--format=text"])
        data = json.loads(out)

        results = []
        for export in data.get("data", []):
            for fn in export.get("functions", []):
                name = fn.get("name", "?")
                count = int(fn.get("count", 0))
                filenames = fn.get("filenames", []) or ["?"]
                fabs = os.path.abspath(filenames[0])
                rel = rel_to_root(self.cfg, fabs)
                start, end = _region_span(fn.get("regions", []))
                results.append(FunctionCoverage(
                    file=rel, name=name, start_line=start, end_line=end,
                    hits=count,
                ))
        return results


def _region_span(regions):
    if not regions:
        return (0, 0)
    starts = [r[0] for r in regions if len(r) >= 4]
    ends = [r[2] for r in regions if len(r) >= 4]
    return (min(starts) if starts else 0, max(ends) if ends else 0)
