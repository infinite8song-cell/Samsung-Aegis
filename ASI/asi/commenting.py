"""Deterministic, language-aware commenting-out of dead functions.

This is the *safe* half of the refactor stage: given the exact line ranges of
the dead functions from the report, it disables them without any model in the
loop, so the commenting is always correct regardless of what the LLM does with
the rest of the file.

Comment styles per language:
  * Python           -> prefix each line with ``# ``
  * C / C++          -> wrap the block in ``#if 0 ... #endif`` (idiomatic,
                        survives any inner comments/strings)
  * //-comment langs -> prefix each line with ``// ``
"""

from __future__ import annotations

_HASH = "hash"        # Python-style, prefix each line with '# '
_IF0 = "cpp_if0"      # C/C++, wrap in #if 0 / #endif
_SLASH = "slash"      # prefix each line with '// '

_STYLE_BY_EXT = {
    "py": _HASH, "pyi": _HASH, "pyx": _HASH,
    "c": _IF0, "h": _IF0, "cpp": _IF0, "cc": _IF0, "cxx": _IF0,
    "hpp": _IF0, "hh": _IF0, "hxx": _IF0,
    "js": _SLASH, "jsx": _SLASH, "ts": _SLASH, "tsx": _SLASH,
    "java": _SLASH, "go": _SLASH, "rs": _SLASH, "cs": _SLASH,
    "kt": _SLASH, "kts": _SLASH, "swift": _SLASH, "scala": _SLASH,
}

_TAG = "ASI: dead code (never executed by the test-vector corpus)"


def style_for(ext: str) -> str:
    return _STYLE_BY_EXT.get(ext.lower().lstrip("."), _SLASH)


def comment_out(text: str, dead: list, ext: str) -> str:
    """Return ``text`` with each dead function commented out.

    ``dead`` is a list of ``(start_line, end_line, name)`` triples, 1-based and
    inclusive, as produced by the analysis report.
    """
    style = style_for(ext)
    # Split preserving a trailing-newline marker so we can rejoin faithfully.
    had_trailing_nl = text.endswith("\n")
    lines = text.split("\n")
    if had_trailing_nl:
        lines.pop()  # drop the empty element created by the trailing newline

    # Work bottom-up so earlier insertions don't shift the line numbers of
    # functions we haven't handled yet. Ignore malformed / overlapping ranges.
    for start, end, name in sorted(dead, key=lambda d: -d[0]):
        if start < 1 or end < start or end > len(lines):
            continue
        _apply(lines, start, end, name, style)

    out = "\n".join(lines)
    if had_trailing_nl:
        out += "\n"
    return out


def _apply(lines: list, start: int, end: int, name: str, style: str) -> None:
    s0 = start - 1          # 0-based first line
    if style == _IF0:
        lines.insert(end, "#endif /* %s : end of '%s' */" % (_TAG, name))
        lines.insert(s0, "#if 0 /* %s : '%s' */" % (_TAG, name))
        return

    prefix = "# " if style == _HASH else "// "
    marker = "# " if style == _HASH else "// "
    lines.insert(end, "%s--- %s : end of '%s' ---" % (marker, _TAG, name))
    for i in range(s0, end):
        lines[i] = prefix + lines[i]
    lines.insert(s0, "%s--- %s : '%s' ---" % (marker, _TAG, name))
