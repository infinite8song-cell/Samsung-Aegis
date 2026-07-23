"""Resolve which source files make up the analysis universe.

The set of source files defines *which functions are candidates for being
dead*. A function only counts as dead code if (a) it is defined in one of these
files and (b) it was never executed by the corpus.
"""

from __future__ import annotations

import glob
import os

from .config import Config


def resolve_sources(cfg: Config) -> list:
    include = cfg.get("sources", "include", default=[])
    exclude = cfg.get("sources", "exclude", default=[])
    if isinstance(include, str):
        include = [include]
    if isinstance(exclude, str):
        exclude = [exclude]
    if not include:
        return []

    found = []
    seen = set()
    for pattern in include:
        for p in glob.glob(cfg.path(pattern), recursive=True):
            ap = os.path.abspath(p)
            if os.path.isfile(ap) and ap not in seen:
                seen.add(ap)
                found.append(ap)

    ex_abs = []
    for pattern in exclude:
        ex_abs.extend(os.path.abspath(p) for p in glob.glob(cfg.path(pattern), recursive=True))
    ex_set = set(ex_abs)

    result = [p for p in found if p not in ex_set]
    result.sort()
    return result


def rel_to_root(cfg: Config, abspath: str) -> str:
    try:
        return os.path.relpath(abspath, cfg.root)
    except ValueError:
        return abspath
