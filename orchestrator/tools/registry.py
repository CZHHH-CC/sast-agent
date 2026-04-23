"""Tool registry + built-in Read / Glob / Grep implementations.

Every tool is a pure async callable that takes (cwd, arguments) and returns
a string result. The runtime handles JSON-schema declarations and error
formatting centrally; tools only do the work.

Everything here is sandboxed by `cwd`: paths are resolved relative to cwd
and must stay inside it. This prevents an agent from reading /etc/passwd
even if it tries.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from ..llm.base import ToolDef


ToolFn = Callable[[Path, dict[str, Any]], Awaitable[str]]


@dataclass
class RegisteredTool:
    defn: ToolDef
    fn: ToolFn


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, RegisteredTool] = {}

    def register(self, defn: ToolDef, fn: ToolFn) -> None:
        self._tools[defn.name] = RegisteredTool(defn=defn, fn=fn)

    def tool_defs(self) -> list[ToolDef]:
        return [t.defn for t in self._tools.values()]

    def get(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name)

    async def execute(
        self, name: str, cwd: Path, arguments: dict[str, Any]
    ) -> tuple[str, bool]:
        """Returns (output, is_error)."""
        tool = self.get(name)
        if tool is None:
            return (f"Tool '{name}' not registered.", True)
        try:
            out = await tool.fn(cwd, arguments)
            return (out, False)
        except _ToolError as e:
            return (str(e), True)
        except Exception as e:
            return (f"{type(e).__name__}: {e}", True)


class _ToolError(Exception):
    """Raised by tool impls for expected errors (bad args, path outside cwd, ...)."""


# ---------- helpers ----------


def _resolve_inside(cwd: Path, rel_or_abs: str) -> Path:
    """Resolve a user-supplied path and ensure it's inside cwd."""
    cwd = cwd.resolve()
    p = (cwd / rel_or_abs).resolve() if not Path(rel_or_abs).is_absolute() else Path(rel_or_abs).resolve()
    try:
        p.relative_to(cwd)
    except ValueError as e:
        raise _ToolError(f"path {rel_or_abs!r} escapes the scan root") from e
    return p


# ---------- tools ----------


_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "file_path": {"type": "string", "description": "Path relative to repo root."},
        "offset": {"type": "integer", "description": "1-based line to start from.", "default": 1},
        "limit": {
            "type": "integer",
            "description": (
                "Max lines to return. Default 800. Pass a specific range + offset "
                "to page through a large file instead of truncating arbitrarily."
            ),
            "default": 800,
        },
    },
    "required": ["file_path"],
}


# Paging defaults (P1-6): instead of a hard 30K char truncation at the
# tool-output layer, we expose explicit pagination via offset/limit. The
# header tells the agent the total line count and how to read the rest.
DEFAULT_READ_LIMIT = 800
MAX_READ_LIMIT = 4000  # hard ceiling per call, to keep a single Read bounded


async def _read_impl(cwd: Path, args: dict[str, Any]) -> str:
    p = _resolve_inside(cwd, args["file_path"])
    if not p.exists():
        raise _ToolError(f"file not found: {p.relative_to(cwd)}")
    if not p.is_file():
        raise _ToolError(f"not a regular file: {p.relative_to(cwd)}")
    offset = max(1, int(args.get("offset", 1)))
    limit = max(1, min(MAX_READ_LIMIT, int(args.get("limit", DEFAULT_READ_LIMIT))))

    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise _ToolError(f"read error: {e}")

    lines = text.splitlines()
    total = len(lines)
    if offset > total:
        return (
            f"# {p.relative_to(cwd)}  (empty window: offset={offset} > total_lines={total})\n"
        )
    end = min(total, offset - 1 + limit)
    selected = lines[offset - 1 : end]
    width = max(4, len(str(end)))
    rendered = "\n".join(
        f"{str(i + offset).rjust(width)}\t{line}" for i, line in enumerate(selected)
    )
    more_hint = ""
    if end < total:
        remaining = total - end
        more_hint = (
            f"\n# … {remaining} more line(s). "
            f"Call Read again with offset={end + 1} to continue."
        )
    header = f"# {p.relative_to(cwd)}  (lines {offset}-{end} of {total})\n"
    return header + rendered + more_hint


_GLOB_SCHEMA = {
    "type": "object",
    "properties": {
        "pattern": {"type": "string", "description": "Glob pattern, e.g. 'src/**/*.java'."},
    },
    "required": ["pattern"],
}


async def _glob_impl(cwd: Path, args: dict[str, Any]) -> str:
    pattern = args["pattern"]
    # rglob-style: support ** recursion
    matches: list[str] = []
    cwd = cwd.resolve()
    for p in cwd.rglob("*"):
        if not p.is_file():
            continue
        rel = p.resolve().relative_to(cwd).as_posix()
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(p.name, pattern):
            matches.append(rel)
        if len(matches) >= 500:
            break
    matches.sort()
    if not matches:
        return "(no matches)"
    return "\n".join(matches)


_GREP_SCHEMA = {
    "type": "object",
    "properties": {
        "pattern": {"type": "string", "description": "Regex pattern."},
        "path": {"type": "string", "description": "Subdir to search. Defaults to repo root.", "default": "."},
        "glob": {"type": "string", "description": "Optional filename glob filter.", "default": ""},
        "context": {"type": "integer", "description": "Lines of context around each match.", "default": 0},
        "max_results": {"type": "integer", "default": 100},
    },
    "required": ["pattern"],
}


async def _grep_impl(cwd: Path, args: dict[str, Any]) -> str:
    pattern = args["pattern"]
    try:
        regex = re.compile(pattern)
    except re.error as e:
        raise _ToolError(f"bad regex: {e}")

    sub = _resolve_inside(cwd, args.get("path") or ".")
    glob_filter = args.get("glob") or ""
    ctx = max(0, int(args.get("context", 0)))
    max_results = max(1, int(args.get("max_results", 100)))

    if sub.is_file():
        files = [sub]
    else:
        files = [p for p in sub.rglob("*") if p.is_file()]

    if glob_filter:
        files = [
            p for p in files
            if fnmatch.fnmatch(p.name, glob_filter)
            or fnmatch.fnmatch(p.resolve().relative_to(cwd.resolve()).as_posix(), glob_filter)
        ]

    # skip obvious binary + common noise dirs
    SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "target", "build", "dist"}
    hits: list[str] = []
    for fp in sorted(files):
        if any(part in SKIP_DIRS for part in fp.parts):
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        rel = fp.resolve().relative_to(cwd.resolve()).as_posix()
        for i, line in enumerate(lines):
            if regex.search(line):
                if ctx == 0:
                    hits.append(f"{rel}:{i+1}: {line}")
                else:
                    lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
                    block = "\n".join(f"{rel}:{j+1}: {lines[j]}" for j in range(lo, hi))
                    hits.append(block)
                if len(hits) >= max_results:
                    break
        if len(hits) >= max_results:
            break
    if not hits:
        return "(no matches)"
    return "\n".join(hits[:max_results])


def build_default_readonly_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(
        ToolDef(name="Read", description="Read a file with optional offset/limit.", input_schema=_READ_SCHEMA),
        _read_impl,
    )
    reg.register(
        ToolDef(name="Glob", description="Glob files by pattern (supports **).", input_schema=_GLOB_SCHEMA),
        _glob_impl,
    )
    reg.register(
        ToolDef(
            name="Grep",
            description="Regex search across files with optional glob filter and context.",
            input_schema=_GREP_SCHEMA,
        ),
        _grep_impl,
    )
    # Semantic tools (P2-7 / P2-8). Imported lazily to avoid cycles on startup.
    from .semantic_tools import register_semantic_tools
    register_semantic_tools(reg)
    return reg
