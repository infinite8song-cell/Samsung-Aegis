"""Generate initial fuzzing corpus from diff content and analysis findings."""

import hashlib
import logging
import struct
from pathlib import Path

from gerrit_fuzzer.gerrit_client import GerritChange
from gerrit_fuzzer.harness_generator import HarnessInfo
from gerrit_fuzzer.metis_analyzer import AnalysisResult

logger = logging.getLogger(__name__)


class CorpusGenerator:
    """Generates initial fuzzing corpus seeds from diff and analysis data."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(self, change: GerritChange, analysis: AnalysisResult,
                 harnesses: list[HarnessInfo]) -> dict[str, Path]:
        """Generate corpus directories for each harness.

        Returns mapping of harness_name -> corpus_directory.
        """
        corpus_map = {}

        for harness in harnesses:
            corpus_dir = self.output_dir / f"corpus_{harness.name}"
            corpus_dir.mkdir(parents=True, exist_ok=True)

            seeds = []

            # 1. Extract seeds from diff hunks (added lines)
            seeds.extend(self._seeds_from_diff(change, harness.target_file))

            # 2. Extract seeds from finding snippets
            seeds.extend(self._seeds_from_findings(harness))

            # 3. Generate structural seeds based on finding categories
            seeds.extend(self._seeds_from_categories(harness, analysis))

            # 4. Add minimal / boundary seeds
            seeds.extend(self._boundary_seeds())

            # Write seeds to corpus directory
            for i, seed_data in enumerate(seeds):
                if not seed_data:
                    continue
                seed_hash = hashlib.sha256(seed_data).hexdigest()[:12]
                seed_file = corpus_dir / f"seed_{i:04d}_{seed_hash}"
                seed_file.write_bytes(seed_data)

            logger.info("Generated %d corpus seeds for %s",
                        len(seeds), harness.name)
            corpus_map[harness.name] = corpus_dir

        return corpus_map

    def _seeds_from_diff(self, change: GerritChange,
                         target_file: str) -> list[bytes]:
        """Extract seed data from added lines in the diff."""
        seeds = []
        for fd in change.file_diffs:
            if fd.new_path != target_file:
                continue
            for hunk in fd.hunks:
                added = []
                for line in hunk.lines:
                    if line.startswith("+"):
                        added.append(line[1:])
                if added:
                    combined = "\n".join(added)
                    seeds.append(combined.encode("utf-8", errors="replace"))
                    # Also add individual lines as seeds
                    for line in added:
                        stripped = line.strip()
                        if stripped and len(stripped) > 3:
                            seeds.append(stripped.encode("utf-8", errors="replace"))
        return seeds

    def _seeds_from_findings(self, harness: HarnessInfo) -> list[bytes]:
        """Extract seeds from code snippets in findings."""
        seeds = []
        for finding in harness.findings:
            if finding.snippet:
                seeds.append(finding.snippet.encode("utf-8", errors="replace"))
        for hint in harness.corpus_hints:
            if hint:
                seeds.append(hint.encode("utf-8", errors="replace"))
        return seeds

    def _seeds_from_categories(self, harness: HarnessInfo,
                               analysis: AnalysisResult) -> list[bytes]:
        """Generate targeted seeds based on vulnerability categories."""
        seeds = []
        categories = {f.category for f in harness.findings}

        if categories & {"buffer-overflow", "heap-overflow", "stack-overflow",
                         "out-of-bounds"}:
            # Seeds with various lengths to trigger boundary conditions
            seeds.append(b"A" * 16)
            seeds.append(b"A" * 128)
            seeds.append(b"A" * 256)
            seeds.append(b"A" * 1024)
            seeds.append(b"A" * 4096)
            # Pattern with embedded nulls
            seeds.append(b"B" * 64 + b"\x00" + b"C" * 64)

        if categories & {"integer-overflow", "integer-underflow"}:
            # Edge-case integer values
            for val in [0, 1, -1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                        0x7FFFFFFFFFFFFFFF]:
                seeds.append(struct.pack("<q", val & 0xFFFFFFFFFFFFFFFF))
                seeds.append(struct.pack("<I", val & 0xFFFFFFFF))
            # Two integers packed together
            seeds.append(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF))
            seeds.append(struct.pack("<II", 0x7FFFFFFF, 2))

        if categories & {"format-string"}:
            seeds.append(b"%s%s%s%s%s%s%s%s%s%s")
            seeds.append(b"%x%x%x%x%x%x%x%x")
            seeds.append(b"%n%n%n%n")
            seeds.append(b"%.999999f")
            seeds.append(b"AAAA" + b"%08x." * 20)

        if categories & {"null-dereference"}:
            seeds.append(b"\x00" * 8)
            seeds.append(b"\x00")
            seeds.append(struct.pack("<Q", 0))

        if categories & {"use-after-free", "double-free"}:
            # Sequences that might trigger allocation patterns
            for size in [8, 16, 32, 64, 128, 256]:
                seeds.append(bytes(range(256))[:size])

        if categories & {"memory-corruption", "uninitialized-memory"}:
            seeds.append(b"\xDE\xAD\xBE\xEF" * 64)
            seeds.append(b"\x00" * 256)
            seeds.append(bytes(range(256)))

        return seeds

    def _boundary_seeds(self) -> list[bytes]:
        """Generate universal boundary-value seeds."""
        return [
            b"",
            b"\x00",
            b"\xff",
            b"\x00\x00\x00\x00",
            b"\xff\xff\xff\xff",
            bytes(range(256)),
            b"Hello, World!",
        ]
