"""Stable fingerprints for findings, resilient to line-number drift."""

from __future__ import annotations

import hashlib
import re


_WHITESPACE_RE = re.compile(r"\s+")
_IDENT_RE = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")


def normalize_snippet(snippet: str) -> str:
    """Normalize a code snippet so cosmetic edits don't break fingerprints.

    - collapse whitespace
    - lowercase
    - replace identifiers with a placeholder token, EXCEPT for a short
      allowlist of security-critical API names that we want to keep as
      part of the fingerprint signal
    """
    keep = {
        # SQL
        "executequery", "executeupdate", "preparestatement", "createnativequery",
        "createquery", "queryforlist", "jdbctemplate", "statement",
        # Command
        "runtime", "exec", "processbuilder", "system", "popen", "subprocess",
        # XSS
        "innerhtml", "dangerouslysetinnerhtml", "vhtml", "document", "write",
        "eval", "function",
        # Path
        "file", "fileinputstream", "fileoutputstream", "readfile",
        # SSRF
        "openconnection", "resttemplate", "httpclient", "fetch", "axios",
        # Deser
        "objectinputstream", "readobject", "pickle", "loads", "unserialize",
        # Auth
        "permitall", "ignoreauth",
    }

    def repl(m: re.Match[str]) -> str:
        tok = m.group(0).lower()
        return tok if tok in keep else "IDENT"

    lowered = snippet.lower()
    masked = _IDENT_RE.sub(repl, lowered)
    # Strip ALL whitespace — we only care about the token sequence, so any
    # whitespace drift (indentation, spaces around punctuation, line breaks)
    # collapses to the same fingerprint.
    return _WHITESPACE_RE.sub("", masked)


def make_fingerprint(*, sink_type: str, file: str, snippet: str) -> str:
    """Deterministic 16-hex-char fingerprint for a finding."""
    file_norm = file.replace("\\", "/").lower()
    payload = f"{sink_type}|{file_norm}|{normalize_snippet(snippet)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
