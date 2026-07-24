"""LLM client for the refactor stage.

Uses the official Anthropic Python SDK (imported lazily so ASI's core stays
dependency-free — only the LLM refactor path needs it). A ``mock`` provider is
available for tests and dry runs, selected via ``llm.provider`` in the config
or the ``ASI_LLM_PROVIDER`` environment variable.
"""

from __future__ import annotations

import os
import re

# Delimiters wrapping the file content in the prompt. The model is told to emit
# only the file body; the mock provider keys off these to echo it back.
FILE_OPEN = "<<<ASI_FILE_BEGIN>>>"
FILE_CLOSE = "<<<ASI_FILE_END>>>"

_DEFAULT_MODEL = "claude-opus-4-8"


class LLMError(RuntimeError):
    pass


class AnthropicClient:
    """Refactor a file via the Anthropic Messages API (streaming)."""

    def __init__(self, cfg):
        self.model = cfg.get("llm", "model", default=_DEFAULT_MODEL)
        self.effort = cfg.get("llm", "effort", default="high")
        self.max_tokens = int(cfg.get("llm", "max_tokens", default=32000))
        try:
            import anthropic  # noqa: F401
        except Exception as exc:  # pragma: no cover - depends on user env
            raise LLMError(
                "the refactor stage needs the Anthropic SDK: pip install anthropic\n"
                "(or run with --comment-only / llm.provider=mock to skip the LLM)"
            ) from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic()

    def complete(self, system: str, user: str) -> str:
        # Stream so large whole-file outputs don't hit request timeouts; adaptive
        # thinking lets the model reason about behaviour preservation as needed.
        with self._client.messages.stream(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            messages=[{"role": "user", "content": user}],
        ) as stream:
            message = stream.get_final_message()
        return "".join(b.text for b in message.content if b.type == "text")


class MockClient:
    """Deterministic stand-in used by tests and ``--dry-run`` plumbing checks.

    Echoes back the file content it was given unchanged (as if the model chose
    to make no edits), which exercises the full write/verify/fallback path
    without any network call.
    """

    def __init__(self, cfg=None):
        pass

    def complete(self, system: str, user: str) -> str:
        m = re.search(re.escape(FILE_OPEN) + r"\n(.*)\n" + re.escape(FILE_CLOSE),
                      user, re.DOTALL)
        return m.group(1) if m else user


def get_client(cfg):
    provider = os.environ.get("ASI_LLM_PROVIDER") or cfg.get("llm", "provider", default="anthropic")
    if provider == "mock":
        return MockClient(cfg)
    if provider == "anthropic":
        return AnthropicClient(cfg)
    raise LLMError("unknown llm.provider %r (use 'anthropic' or 'mock')" % provider)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM = """You are a meticulous refactoring assistant. You refactor one source \
file at a time while preserving its observable behaviour exactly.

Hard rules — follow all of them:
1. Output ONLY the complete, final content of the file. No markdown fences, no \
commentary, no explanation before or after.
2. Preserve the public API exactly: do not rename, remove, or change the \
signature of any function, method, class, or exported symbol that is not \
already commented out.
3. Do NOT change the observable behaviour of any live (non-commented) code.
4. The functions already commented out with an "ASI: dead code" marker are \
proven-unused. Leave them commented out — do not delete them and do not \
re-enable them.
5. Keep the file in its original language. Keep license headers and meaningful \
comments.
6. You MAY improve readability within these limits: clarify local variable \
names, remove redundant local code, tidy formatting, and add brief clarifying \
comments. When in doubt, make no change.
"""


def build_prompt(filename: str, language: str, dead_names: list, file_text: str):
    """Return ``(system, user)`` for refactoring one file."""
    dead_list = ", ".join(dead_names) if dead_names else "(none in this file)"
    user = (
        "Refactor the following file: `%s` (language: %s).\n\n"
        "Dead functions already commented out (leave them commented): %s\n\n"
        "Return only the full file content between the markers, nothing else.\n\n"
        "%s\n%s\n%s\n"
        % (filename, language, dead_list, FILE_OPEN, file_text, FILE_CLOSE)
    )
    return _SYSTEM, user


def strip_fences(text: str) -> str:
    """Remove an accidental leading/trailing markdown code fence, if present."""
    t = text.strip("\n")
    # Pull content out of the markers if the model echoed them.
    m = re.search(re.escape(FILE_OPEN) + r"\n?(.*)\n?" + re.escape(FILE_CLOSE),
                  t, re.DOTALL)
    if m:
        t = m.group(1)
    lines = t.split("\n")
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    out = "\n".join(lines)
    if not out.endswith("\n"):
        out += "\n"
    return out
