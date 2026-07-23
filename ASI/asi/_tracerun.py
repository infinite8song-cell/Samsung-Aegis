"""Runtime tracer used by the ``pytrace`` backend.

Invoked once per test vector as a subprocess:

    python -m asi._tracerun --out <counts.json> --root <project_root> -- \
        path/to/target.py [args...]

It installs a ``sys.settrace`` hook that records every *function entry* (the
``call`` event), then runs the target script exactly as ``python target.py
args`` would. The result is a JSON object mapping ``"<abs file>::<firstlineno>
::<name>"`` to a call count, written to ``--out``. The engine unions these
across all vectors to decide which functions ever ran.

Returning ``None`` from the trace hook disables per-line tracing, so the only
overhead is one Python call per function entry -- cheap enough for large
corpora.
"""

from __future__ import annotations

import json
import os
import sys


def _run(out_path: str, root: str | None, target: str, targ_args: list) -> None:
    root_abs = os.path.abspath(root) + os.sep if root else None
    counts: dict = {}

    def tracer(frame, event, arg):
        if event == "call":
            co = frame.f_code
            fn = os.path.abspath(co.co_filename)
            if root_abs is None or fn.startswith(root_abs):
                key = "%s::%d::%s" % (fn, co.co_firstlineno, co.co_name)
                counts[key] = counts.get(key, 0) + 1
        return None

    target_abs = os.path.abspath(target)
    sys.argv = [target] + list(targ_args)
    # Make sibling imports of the target resolve like a normal `python x.py`.
    sys.path.insert(0, os.path.dirname(target_abs) or ".")

    with open(target_abs, "r", encoding="utf-8") as f:
        code = compile(f.read(), target_abs, "exec")
    module_globals = {
        "__name__": "__main__",
        "__file__": target_abs,
        "__builtins__": __builtins__,
    }

    # Run the target exactly as `python target.py args` would, under the tracer.
    sys.settrace(tracer)
    try:
        exec(code, module_globals)
    except SystemExit:
        pass
    finally:
        sys.settrace(None)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(counts, f)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    out_path = None
    root = None
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--out":
            out_path = argv[i + 1]; i += 2
        elif a == "--root":
            root = argv[i + 1]; i += 2
        elif a == "--":
            rest = argv[i + 1:]; break
        else:
            rest = argv[i:]; break

    if not out_path or not rest:
        sys.stderr.write("usage: python -m asi._tracerun --out F [--root R] -- target.py [args]\n")
        return 2

    _run(out_path, root, rest[0], rest[1:])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
