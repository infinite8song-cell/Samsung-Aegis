"""Replay the test-vector corpus against the target program.

This module is backend-agnostic: it just knows how to turn one vector into one
process invocation. Backends influence the invocation through two hooks --
``wrap_command`` (e.g. to run under a tracer) and ``per_run_env`` (e.g. to give
each run its own coverage-output file).
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys

from .config import Config
from .model import RunStats


def run_corpus(cfg: Config, backend, vectors: list, verbose: bool = False) -> RunStats:
    run_cmd = cfg.require("run", "command")
    stdin_mode = bool(cfg.get("run", "stdin", default=False))
    per_vector = bool(cfg.get("run", "per_vector", default=True))
    workdir = cfg.path(cfg.get("run", "workdir", default="."))
    timeout = cfg.get("run", "timeout", default=120)
    allow_failure = bool(cfg.get("run", "allow_failure", default=True))
    extra_env = cfg.get("run", "env", default={}) or {}

    base_env = dict(os.environ)
    base_env.update({str(k): str(v) for k, v in extra_env.items()})

    stats = RunStats()

    if not per_vector:
        # Single invocation that consumes the whole corpus itself.
        _one(cfg, backend, run_cmd, None, 0, workdir, base_env,
             stdin_mode, timeout, allow_failure, stats, verbose)
        return stats

    for idx, vector in enumerate(vectors):
        _one(cfg, backend, run_cmd, vector, idx, workdir, base_env,
             stdin_mode, timeout, allow_failure, stats, verbose)
    return stats


def _one(cfg, backend, run_cmd, vector, idx, workdir, base_env,
         stdin_mode, timeout, allow_failure, stats, verbose):
    stats.total += 1

    if vector is not None and not stdin_mode:
        cmd = run_cmd.replace("{input}", shlex.quote(vector))
    else:
        cmd = run_cmd

    cmd = backend.wrap_command(cmd, idx, vector)
    env = dict(base_env)
    env.update({str(k): str(v) for k, v in backend.per_run_env(idx, vector).items()})

    stdin_fh = None
    try:
        if stdin_mode and vector is not None:
            stdin_fh = open(vector, "rb")
        proc = subprocess.run(
            cmd, shell=True, cwd=workdir, env=env,
            stdin=stdin_fh,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        rc = proc.returncode
        if rc == 0:
            stats.ok += 1
            if verbose:
                sys.stderr.write("  [ok ] %s\n" % (vector or "<corpus>"))
        else:
            stats.failed += 1
            tail = (proc.stdout or b"").decode("utf-8", "replace")[-400:]
            stats.failures.append((vector, rc, tail))
            sys.stderr.write("  [rc%d] %s\n" % (rc, vector or "<corpus>"))
            if not allow_failure:
                raise RuntimeError("run failed (allow_failure=false): %s" % (vector,))
    except subprocess.TimeoutExpired:
        stats.failed += 1
        stats.failures.append((vector, "timeout", ""))
        sys.stderr.write("  [time] %s\n" % (vector or "<corpus>"))
        if not allow_failure:
            raise
    finally:
        if stdin_fh is not None:
            stdin_fh.close()
