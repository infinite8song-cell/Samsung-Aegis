"""Backend registry.

To add support for a new language/toolchain, implement a ``Backend`` subclass
(see ``base.py``) and register it here. Nothing else in ASI needs to change --
that is the whole point of the pluggable design.
"""

from __future__ import annotations

from .base import Backend
from .gcov import GcovBackend
from .llvmcov import LlvmCovBackend
from .pytrace import PyTraceBackend

_REGISTRY = {
    GcovBackend.key: GcovBackend,
    LlvmCovBackend.key: LlvmCovBackend,
    PyTraceBackend.key: PyTraceBackend,
}


def available() -> list:
    return sorted(_REGISTRY)


def get_backend(key: str, cfg, ctx) -> Backend:
    try:
        cls = _REGISTRY[key]
    except KeyError:
        raise ValueError(
            "unknown backend %r (available: %s)" % (key, ", ".join(available()))
        )
    return cls(cfg, ctx)
