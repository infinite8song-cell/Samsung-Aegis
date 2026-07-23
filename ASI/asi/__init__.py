"""ASI - Aegis Static/dynamic Inspector.

A language-pluggable, dependency-free harness that finds *dead code* by the
only criterion that actually proves a function is unused: it is never executed
when the project's test-vector inputs are run.

The public entry point is the command line interface (`python -m asi`), but the
building blocks are importable:

    from asi.engine import analyze
    from asi.config import load_config

See ASI/README.md for the design rationale and ASI/GUIDE.md for the full
configuration reference and instructions for adding new language backends.
"""

__version__ = "1.0.0"
