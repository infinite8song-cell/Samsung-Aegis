"""Enumerate the functions defined in a Python source file.

Used by the ``pytrace`` backend to build the universe of candidate functions.
The reported ``start`` line is deliberately the line of the *first decorator*
(falling back to the ``def`` line for undecorated functions), because that is
exactly what CPython stores as ``code.co_firstlineno`` -- which is the key the
runtime tracer records. Matching the two on ``(file, start)`` therefore needs
no fuzzy heuristics.
"""

from __future__ import annotations

import ast


def enumerate_functions(path: str) -> list:
    """Return ``[(qualified_name, start_line, end_line), ...]``."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError:
        return []

    out = []
    stack = []

    def start_line(node):
        lines = [d.lineno for d in node.decorator_list] + [node.lineno]
        return min(lines)

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = ".".join(stack + [child.name])
                end = getattr(child, "end_lineno", None) or child.lineno
                out.append((qual, start_line(child), end))
                stack.append(child.name)
                visit(child)
                stack.pop()
            elif isinstance(child, ast.ClassDef):
                stack.append(child.name)
                visit(child)
                stack.pop()
            else:
                visit(child)

    visit(tree)
    return out
