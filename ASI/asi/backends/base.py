"""Backend interface and shared helpers.

A backend answers one question for a given language/toolchain: *after replaying
the corpus, which functions ran and how often?* Everything else (resolving
vectors, driving the run loop, reporting) is backend independent.

Lifecycle, in order:

    prepare()        # build / instrument the target (once)
    before_run()     # reset stale coverage counters (once)
    # ... engine replays every vector; for each run the runner calls:
    wrap_command(cmd, idx, vector) -> cmd
    per_run_env(idx, vector)       -> dict
    # ...
    collect() -> list[FunctionCoverage]
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys

from ..config import Config


class Backend:
    key = "base"

    def __init__(self, cfg: Config, ctx):
        self.cfg = cfg
        self.ctx = ctx

    # -- lifecycle hooks (override as needed) ---------------------------
    def prepare(self) -> None:
        pass

    def before_run(self) -> None:
        pass

    def wrap_command(self, command: str, index: int, vector) -> str:
        return command

    def per_run_env(self, index: int, vector) -> dict:
        return {}

    def collect(self) -> list:
        raise NotImplementedError

    # -- helpers --------------------------------------------------------
    def _build(self) -> None:
        """Run the optional user-supplied build/instrumentation command."""
        build_cmd = self.cfg.get("build", "command")
        if not build_cmd:
            return
        workdir = self.cfg.path(self.cfg.get("build", "workdir", default="."))
        env = dict(os.environ)
        env.update({str(k): str(v) for k, v in (self.cfg.get("build", "env", default={}) or {}).items()})
        sys.stderr.write("[asi] build: %s\n" % build_cmd)
        proc = subprocess.run(build_cmd, shell=True, cwd=workdir, env=env)
        if proc.returncode != 0:
            raise RuntimeError("build command failed (rc=%d): %s" % (proc.returncode, build_cmd))

    def _sh(self, args, **kwargs):
        """Run a command, capturing stdout as text. Raises on failure."""
        proc = subprocess.run(args, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, **kwargs)
        if proc.returncode != 0:
            raise RuntimeError(
                "command failed (rc=%d): %s\n%s"
                % (proc.returncode,
                   args if isinstance(args, str) else shlex.join(args),
                   proc.stderr.decode("utf-8", "replace"))
            )
        return proc.stdout.decode("utf-8", "replace")
