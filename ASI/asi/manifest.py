"""Resolve the list of test-vector input files.

Two ways to describe the corpus, matching how test vectors are usually shipped:

1. A **manifest text file** that lists one vector path per line. This is the
   primary mode: the user said the vector paths are already collected in a
   separate text file. Blank lines and ``#`` comments are ignored. A line may
   itself be a glob (``group_*/**/*.bin``) and will be expanded.

2. A **directory scan**: point ASI at the root folder of the (arbitrarily
   nested) vector tree and give a glob such as ``**/*``.

Either way the result is a de-duplicated, order-stable list of absolute paths.
"""

from __future__ import annotations

import glob
import os

from .config import Config


class ManifestError(Exception):
    pass


def resolve_vectors(cfg: Config) -> list:
    manifest = cfg.get("vectors", "manifest")
    directory = cfg.get("vectors", "dir")

    if manifest:
        vectors = _from_manifest(cfg, manifest)
    elif directory:
        vectors = _from_directory(cfg, directory)
    else:
        raise ManifestError(
            "config.vectors needs either 'manifest' (a text file of paths) "
            "or 'dir' (a folder to scan)"
        )

    excludes = cfg.get("vectors", "exclude", default=[])
    if isinstance(excludes, str):
        excludes = [excludes]
    ex_abs = set()
    base = _base_dir(cfg)
    for pattern in excludes:
        pat = pattern if os.path.isabs(pattern) else os.path.join(base, pattern)
        ex_abs.update(os.path.abspath(p) for p in glob.glob(pat, recursive=True))

    result, seen = [], set()
    for v in vectors:
        if v in ex_abs or v in seen:
            continue
        seen.add(v)
        result.append(v)
    return result


def _base_dir(cfg: Config) -> str:
    base = cfg.get("vectors", "base", default=".")
    return cfg.path(base)


def _from_manifest(cfg: Config, manifest: str) -> list:
    manifest_path = cfg.path(manifest)
    if not os.path.isfile(manifest_path):
        raise ManifestError("manifest file not found: %s" % manifest_path)
    base = _base_dir(cfg)

    out = []
    with open(manifest_path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            target = line if os.path.isabs(line) else os.path.join(base, line)
            if glob.has_magic(target):
                matches = sorted(glob.glob(target, recursive=True))
                if not matches:
                    raise ManifestError(
                        "manifest line %d: glob matched nothing: %s" % (lineno, line)
                    )
                out.extend(os.path.abspath(m) for m in matches if os.path.isfile(m))
            else:
                ap = os.path.abspath(target)
                if not os.path.isfile(ap):
                    raise ManifestError(
                        "manifest line %d: vector not found: %s" % (lineno, target)
                    )
                out.append(ap)
    return out


def _from_directory(cfg: Config, directory: str) -> list:
    root = cfg.path(directory)
    if not os.path.isdir(root):
        raise ManifestError("vectors.dir is not a directory: %s" % root)
    pattern = cfg.get("vectors", "glob", default="**/*")
    matches = glob.glob(os.path.join(root, pattern), recursive=True)
    return sorted(os.path.abspath(m) for m in matches if os.path.isfile(m))
