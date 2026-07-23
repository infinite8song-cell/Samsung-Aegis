"""Orchestration: build -> replay corpus -> collect coverage -> report."""

from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass

from .backends import get_backend
from .config import Config
from .manifest import resolve_vectors
from .model import Report
from .runner import run_corpus


@dataclass
class Context:
    root: str
    tmp_dir: str
    asi_pkg_dir: str     # directory that CONTAINS the `asi` package (for PYTHONPATH)
    verbose: bool = False


def _make_context(cfg: Config, verbose: bool) -> Context:
    tmp_dir = cfg.get("workdir_tmp")
    if tmp_dir:
        tmp_dir = cfg.path(tmp_dir)
        os.makedirs(tmp_dir, exist_ok=True)
    else:
        tmp_dir = tempfile.mkdtemp(prefix="asi_")
    asi_pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return Context(root=cfg.root, tmp_dir=tmp_dir, asi_pkg_dir=asi_pkg_dir, verbose=verbose)


def analyze(cfg: Config, verbose: bool = False, skip_build: bool = False) -> Report:
    """Run the full pipeline and return a :class:`Report`."""
    ctx = _make_context(cfg, verbose)
    backend_key = cfg.require("backend")
    backend = get_backend(backend_key, cfg, ctx)

    name = cfg.get("name", default=os.path.basename(cfg.root.rstrip("/")) or "project")

    vectors = resolve_vectors(cfg)
    sys.stderr.write("[asi] %d test vector(s) resolved\n" % len(vectors))
    if not vectors and cfg.get("run", "per_vector", default=True):
        sys.stderr.write("[asi] warning: corpus is empty; every function will look dead\n")

    if not skip_build:
        backend.prepare()
    backend.before_run()

    sys.stderr.write("[asi] replaying corpus with backend '%s'...\n" % backend_key)
    stats = run_corpus(cfg, backend, vectors, verbose=verbose)
    sys.stderr.write("[asi] runs: %d ok, %d failed\n" % (stats.ok, stats.failed))

    functions = backend.collect()
    functions.sort(key=lambda f: (f.file, f.start_line))

    return Report(
        name=name,
        backend=backend_key,
        functions=functions,
        run_stats=stats,
        vectors=vectors,
    )
