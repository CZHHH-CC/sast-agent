"""Lightweight semantic tools: FindFunction, FindCallers, FindImports.

These sit alongside the text tools (Read/Grep/Glob) and give the agent a
structure-aware alternative to "Grep for a token and hope". Implementation
is language-heuristic regex rather than a real AST parser — this keeps the
install clean (no tree-sitter wheels needed) and works across the full
SOURCE_SUFFIXES set. The tool surface is designed to be swap-in-compatible
with a future tree-sitter / Java-Parser backend (see plan P2-7 / P2-8):

  * Input schemas are purely declarative.
  * Outputs are deterministic text blocks with "file:line: snippet" shape,
    same as Grep — so the agent doesn't have to learn new output formats.

What the regex layer actually gets right:
  - Function *definition* detection in Java, Kotlin, JS/TS, Python, Go, PHP,
    Ruby, Rust, C# — by matching language-specific declaration keywords.
  - Call site detection via ``\\b<name>\\s*\\(`` — good enough to surface
    likely callers. False positives possible (comments, strings) but still
    strictly better than unbounded Grep.
  - Imports / uses / requires / from-imports.

What it does NOT do (tree-sitter territory, future work):
  - Method-vs-function disambiguation.
  - Receiver/class-qualified calls (``obj.name(``) filtering.
  - Scope awareness (shadowed names).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..llm.base import ToolDef
from ..scope import SOURCE_SUFFIXES, IGNORED_DIRS


# Cap how many files we scan per call so a misuse doesn't hang the agent loop.
_MAX_SCAN_FILES = 2000
_MAX_RESULTS_DEFAULT = 80


def _iter_source(cwd: Path):
    root = cwd.resolve()
    count = 0
    for p in root.rglob("*"):
        if count >= _MAX_SCAN_FILES:
            return
        if not p.is_file():
            continue
        try:
            rel_parts = p.resolve().relative_to(root).parts
        except ValueError:
            continue
        if any(part in IGNORED_DIRS for part in rel_parts[:-1]):
            continue
        if p.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        yield p
        count += 1


# ---------- function definition patterns, per-language ----------

# Capture-style: we look for a definition-site token followed by the name.
# Keys are lowercase file extensions (without dot).
_FUNCDEF_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "java": [
        re.compile(r"\b(?:public|private|protected|static|final|synchronized|abstract|default|\s)+[\w<>\[\],\s?]+?\s+(\w+)\s*\([^;{]*\)\s*(?:throws [\w,\s.]+)?\s*\{"),
    ],
    "kt": [re.compile(r"\bfun\s+(?:<[^>]+>\s+)?(?:\w+\.)?(\w+)\s*\(")],
    "scala": [re.compile(r"\bdef\s+(\w+)\s*[\[(]")],
    "groovy": [re.compile(r"\bdef\s+(\w+)\s*\(")],
    "js": [
        re.compile(r"\bfunction\s+(\w+)\s*\("),
        re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)"),
        re.compile(r"^\s*(\w+)\s*\([^)]*\)\s*\{", re.MULTILINE),
    ],
    "jsx": None,  # filled below
    "ts": None,
    "tsx": None,
    "mjs": None,
    "cjs": None,
    "py": [
        re.compile(r"^\s*def\s+(\w+)\s*\(", re.MULTILINE),
        re.compile(r"^\s*async\s+def\s+(\w+)\s*\(", re.MULTILINE),
    ],
    "go": [re.compile(r"\bfunc\s+(?:\([^)]+\)\s+)?(\w+)\s*\(")],
    "rb": [re.compile(r"^\s*def\s+(?:self\.)?(\w+)", re.MULTILINE)],
    "php": [re.compile(r"\bfunction\s+(\w+)\s*\(")],
    "cs": [
        re.compile(r"\b(?:public|private|protected|internal|static|virtual|override|async|\s)+[\w<>\[\],\s?]+?\s+(\w+)\s*\([^;{]*\)\s*\{"),
    ],
    "rs": [re.compile(r"\bfn\s+(\w+)\s*[(<]")],
    "vue": None,  # handled as js
    "svelte": None,
}
# JS/TS family share patterns
for _ext in ("jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte"):
    _FUNCDEF_PATTERNS[_ext] = _FUNCDEF_PATTERNS["js"]


# ---------- import / use patterns per-language ----------

_IMPORT_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "java": [re.compile(r"^\s*import\s+([\w.*]+)\s*;", re.MULTILINE)],
    "kt":   [re.compile(r"^\s*import\s+([\w.*]+)", re.MULTILINE)],
    "py":   [
        re.compile(r"^\s*import\s+([\w.,\s]+)", re.MULTILINE),
        re.compile(r"^\s*from\s+([\w.]+)\s+import\s+[\w,*\s]+", re.MULTILINE),
    ],
    "js":   [
        re.compile(r"""^\s*import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]""", re.MULTILINE),
        re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    ],
    "go":   [re.compile(r"""^\s*(?:import\s*)?["']([^"']+)["']""", re.MULTILINE)],
    "rb":   [re.compile(r"""^\s*require(?:_relative)?\s+['"]([^'"]+)['"]""", re.MULTILINE)],
    "php":  [
        re.compile(r"""^\s*use\s+([\w\\]+)""", re.MULTILINE),
        re.compile(r"""\brequire(?:_once)?\s*\(?\s*['"]([^'"]+)['"]"""),
    ],
    "cs":   [re.compile(r"^\s*using\s+([\w.]+)\s*;", re.MULTILINE)],
    "rs":   [re.compile(r"^\s*use\s+([\w:]+)", re.MULTILINE)],
}
for _ext in ("jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte"):
    _IMPORT_PATTERNS[_ext] = _IMPORT_PATTERNS["js"]
for _ext in ("scala", "groovy"):
    _IMPORT_PATTERNS[_ext] = _IMPORT_PATTERNS["java"]


# ---------- helpers ----------


def _ext(p: Path) -> str:
    return p.suffix.lower().lstrip(".")


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _rel(p: Path, cwd: Path) -> str:
    try:
        return p.resolve().relative_to(cwd.resolve()).as_posix()
    except ValueError:
        return str(p)


# ---------- FindFunction ----------


_FIND_FUNCTION_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Function / method name to locate."},
        "file": {
            "type": "string",
            "description": "Optional: restrict search to a single file (relative path).",
        },
        "max_results": {"type": "integer", "default": _MAX_RESULTS_DEFAULT},
    },
    "required": ["name"],
}


async def _find_function_impl(cwd: Path, args: dict[str, Any]) -> str:
    name = str(args["name"]).strip()
    if not name or not re.fullmatch(r"\w+", name):
        return "(bad name — must be a plain identifier)"
    max_results = max(1, int(args.get("max_results", _MAX_RESULTS_DEFAULT)))

    file_filter = args.get("file")
    if file_filter:
        from .registry import _resolve_inside  # local import to avoid cycle
        target = _resolve_inside(cwd, str(file_filter))
        files = [target] if target.is_file() else []
    else:
        files = list(_iter_source(cwd))

    hits: list[str] = []
    for p in files:
        ext = _ext(p)
        patterns = _FUNCDEF_PATTERNS.get(ext)
        if not patterns:
            continue
        text = _read_text(p)
        if text is None:
            continue
        for pat in patterns:
            for m in pat.finditer(text):
                # Group 1 is the captured identifier
                if (m.groupdict().get("name") or (m.group(1) if m.groups() else "")) != name:
                    continue
                ln = _line_at(text, m.start())
                line_text = text.splitlines()[ln - 1] if ln - 1 < len(text.splitlines()) else ""
                hits.append(f"{_rel(p, cwd)}:{ln}: {line_text.strip()}")
                if len(hits) >= max_results:
                    break
            if len(hits) >= max_results:
                break
        if len(hits) >= max_results:
            break

    if not hits:
        return f"(no function named '{name}' found)"
    return "\n".join(hits)


# ---------- FindCallers ----------


_FIND_CALLERS_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Function / method name."},
        "path": {
            "type": "string",
            "description": "Optional: restrict search to a subdirectory.",
        },
        "max_results": {"type": "integer", "default": _MAX_RESULTS_DEFAULT},
    },
    "required": ["name"],
}

_CALLSITE_TEMPLATE = re.compile(r"")  # placeholder; built per-call


async def _find_callers_impl(cwd: Path, args: dict[str, Any]) -> str:
    name = str(args["name"]).strip()
    if not name or not re.fullmatch(r"\w+", name):
        return "(bad name — must be a plain identifier)"
    max_results = max(1, int(args.get("max_results", _MAX_RESULTS_DEFAULT)))

    from .registry import _resolve_inside  # local import to avoid cycle
    sub_arg = args.get("path") or "."
    sub = _resolve_inside(cwd, sub_arg)
    if sub.is_file():
        files = [sub]
    else:
        files = [p for p in _iter_source(sub)]

    call_re = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    # Exclude definition-site lines when possible (reduce noise).
    hits: list[str] = []
    for p in files:
        ext = _ext(p)
        def_patterns = _FUNCDEF_PATTERNS.get(ext) or []
        text = _read_text(p)
        if text is None:
            continue
        lines = text.splitlines()
        # Mark definition lines so we can skip them.
        def_lines: set[int] = set()
        for pat in def_patterns:
            for m in pat.finditer(text):
                if (m.group(1) if m.groups() else "") == name:
                    def_lines.add(_line_at(text, m.start()))
        for i, line in enumerate(lines, start=1):
            if i in def_lines:
                continue
            if call_re.search(line):
                hits.append(f"{_rel(p, cwd)}:{i}: {line.strip()}")
                if len(hits) >= max_results:
                    break
        if len(hits) >= max_results:
            break

    if not hits:
        return f"(no callers of '{name}' found)"
    return "\n".join(hits)


# ---------- FindImports ----------


_FIND_IMPORTS_SCHEMA = {
    "type": "object",
    "properties": {
        "file": {"type": "string", "description": "Relative path to the source file."},
    },
    "required": ["file"],
}


async def _find_imports_impl(cwd: Path, args: dict[str, Any]) -> str:
    from .registry import _resolve_inside
    p = _resolve_inside(cwd, str(args["file"]))
    if not p.is_file():
        return f"(not a file: {args['file']})"
    ext = _ext(p)
    patterns = _IMPORT_PATTERNS.get(ext)
    if not patterns:
        return f"(no import parser registered for .{ext})"
    text = _read_text(p)
    if text is None:
        return "(read error)"

    imports: list[str] = []
    for pat in patterns:
        for m in pat.finditer(text):
            target = (m.group(1) or "").strip()
            # split multi-import "a, b, c"
            for piece in re.split(r"[,\s]+", target):
                piece = piece.strip()
                if piece and piece not in imports:
                    imports.append(piece)

    if not imports:
        return "(no imports detected)"
    return "\n".join(imports)


# ---------- registration ----------


def register_semantic_tools(reg) -> None:
    """Mutate a ToolRegistry to add FindFunction / FindCallers / FindImports."""
    reg.register(
        ToolDef(
            name="FindFunction",
            description=(
                "Locate a function / method *definition* by exact name. Prefer "
                "this over Grep when you want to jump to where a function is "
                "declared. Returns 'path:line: signature' lines."
            ),
            input_schema=_FIND_FUNCTION_SCHEMA,
        ),
        _find_function_impl,
    )
    reg.register(
        ToolDef(
            name="FindCallers",
            description=(
                "List callers of a function / method by exact name (lightweight "
                "call-graph). Excludes the definition site. Useful for source→sink "
                "tracing. Returns 'path:line: code' lines."
            ),
            input_schema=_FIND_CALLERS_SCHEMA,
        ),
        _find_callers_impl,
    )
    reg.register(
        ToolDef(
            name="FindImports",
            description=(
                "List imports / uses / requires declared in a source file. Useful "
                "for figuring out which framework/library a file depends on."
            ),
            input_schema=_FIND_IMPORTS_SCHEMA,
        ),
        _find_imports_impl,
    )
