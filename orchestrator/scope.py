"""Compute the set of files an agent should look at.

Two modes:
  full  — every source file in the repo
  diff  — files touched by `git diff base..head`, optionally expanded with
          1-hop neighbors (files that import or are imported by changed files).
          The MVP only does a cheap import-grep expansion; a proper call graph
          is future work.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable


# Keep this conservative — adding languages is cheap, but each extension
# increases Scanner token cost.
SOURCE_SUFFIXES = {
    ".java", ".kt", ".scala", ".groovy",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".vue", ".svelte",
}

IGNORED_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "target", "build", "dist", "out",
    ".venv", "venv", "__pycache__",
    ".next", ".nuxt", ".svelte-kit",
    "testfixtures",  # don't scan our own fixtures when sast-agent scans itself
}


def _is_source(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_SUFFIXES


def _iter_source_files(root: Path) -> Iterable[Path]:
    root = root.resolve()
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Only consider path parts *relative to the scan root* when deciding
        # to ignore. This lets callers scan INTO e.g. testfixtures/foo/ even
        # though "testfixtures" itself would be ignored at top level.
        try:
            rel_parts = p.resolve().relative_to(root).parts
        except ValueError:
            continue
        if any(part in IGNORED_DIRS for part in rel_parts[:-1]):
            continue
        if _is_source(p):
            yield p


def full_scan_files(repo: Path) -> list[Path]:
    return sorted(_iter_source_files(repo))


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
    )
    return out.stdout


def diff_changed_files(repo: Path, base: str, head: str) -> list[Path]:
    raw = _git(repo, "diff", "--name-only", f"{base}...{head}")
    files = [repo / line.strip() for line in raw.splitlines() if line.strip()]
    return [p for p in files if p.exists() and _is_source(p)]


def expand_neighbors(repo: Path, changed: list[Path], max_neighbors: int = 50) -> list[Path]:
    """Cheap 1-hop expansion: for each changed file, find other source files
    that mention the changed file's stem (likely importers). Capped to keep
    scanner input bounded."""
    if not changed:
        return []
    stems = {p.stem for p in changed}
    neighbors: set[Path] = set()
    for src in _iter_source_files(repo):
        if src in changed:
            continue
        try:
            text = src.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(stem in text for stem in stems):
            neighbors.add(src)
            if len(neighbors) >= max_neighbors:
                break
    return sorted(neighbors)


def diff_scan_files(repo: Path, base: str, head: str) -> list[Path]:
    changed = diff_changed_files(repo, base, head)
    neighbors = expand_neighbors(repo, changed)
    return sorted(set(changed) | set(neighbors))


def cluster_by_directory(files: list[Path], target_batch_size: int = 12) -> list[list[Path]]:
    """Group files into batches such that files sharing a directory tend to land
    in the same batch. Same-directory / same-module files have higher cross-file
    relevance (Controller ↔ Service ↔ DAO), so keeping them together lets the
    Scanner see coherent context in one window.

    Algorithm: bucket by parent dir, then pack buckets greedily. Dirs larger
    than target split evenly; small dirs accumulate into the current batch
    until it reaches ``target_batch_size``.
    """
    if not files:
        return []

    by_dir: dict[Path, list[Path]] = {}
    for f in files:
        by_dir.setdefault(f.parent, []).append(f)

    # Order dirs by size desc → large modules get dedicated batches first, small
    # ones pack efficiently afterward.
    ordered = sorted(by_dir.items(), key=lambda kv: (-len(kv[1]), str(kv[0])))

    batches: list[list[Path]] = []
    current: list[Path] = []
    for _dir, group in ordered:
        group.sort()
        # Big dir: split into dedicated full-size batches.
        if len(group) >= target_batch_size:
            if current:
                batches.append(current)
                current = []
            for i in range(0, len(group), target_batch_size):
                batches.append(group[i : i + target_batch_size])
            continue
        # Small dir: fit into current batch if it doesn't overflow, else flush.
        if len(current) + len(group) > target_batch_size and current:
            batches.append(current)
            current = []
        current.extend(group)
        if len(current) >= target_batch_size:
            batches.append(current)
            current = []
    if current:
        batches.append(current)
    return batches
