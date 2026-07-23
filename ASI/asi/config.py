"""Configuration loading.

A config is a plain JSON document (see ``asi.example.json``). YAML is accepted
too *iff* PyYAML happens to be installed, but JSON keeps the tool dependency
free, which is the whole point of ASI being usable on any code base.
"""

from __future__ import annotations

import json
import os


class ConfigError(Exception):
    pass


class Config:
    """Thin, forgiving wrapper around the parsed config document.

    All path-valued options are resolved relative to ``root`` (which itself
    defaults to the directory containing the config file), so a config can be
    checked in next to the project and stay portable.
    """

    def __init__(self, data: dict, root: str, source_path: str = "<memory>"):
        if not isinstance(data, dict):
            raise ConfigError("config root must be an object/mapping")
        self.data = data
        self.root = os.path.abspath(root)
        self.source_path = source_path

    # -- access helpers -------------------------------------------------
    def get(self, *keys, default=None):
        node = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def require(self, *keys):
        sentinel = object()
        val = self.get(*keys, default=sentinel)
        if val is sentinel:
            raise ConfigError("missing required config key: %s" % ".".join(keys))
        return val

    def path(self, p: str) -> str:
        """Resolve ``p`` relative to the project root."""
        if os.path.isabs(p):
            return p
        return os.path.normpath(os.path.join(self.root, p))


def load_config(path: str) -> Config:
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise ConfigError("config file not found: %s" % path)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    data = _parse(text, path)
    # `root` may be given relative to the config file's directory.
    cfg_dir = os.path.dirname(path)
    root = data.get("root", ".")
    root = root if os.path.isabs(root) else os.path.normpath(os.path.join(cfg_dir, root))
    return Config(data, root, source_path=path)


def _parse(text: str, path: str) -> dict:
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except Exception as exc:  # pragma: no cover - optional path
            raise ConfigError(
                "YAML config requires PyYAML (pip install pyyaml); "
                "or use a .json config instead"
            ) from exc
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError("invalid JSON in %s: %s" % (path, exc)) from exc
