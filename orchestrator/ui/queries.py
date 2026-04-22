"""Read-only SQLite queries against baseline.db.

Opens the DB with `mode=ro` URI so any accidental INSERT/UPDATE in this
module (or downstream) will raise `sqlite3.OperationalError: attempt to
write a readonly database`. That's a load-bearing invariant for UI safety.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class FindingRow:
    fingerprint: str
    status: str  # confirmed | excluded
    severity: str | None
    sink_type: str
    file: str
    line: int | None
    exclusion_category: str | None
    first_seen: float
    last_seen: float
    payload: dict[str, Any]

    @property
    def title(self) -> str:
        return self.payload.get("title") or self.sink_type

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get((self.severity or "").upper(), 99)


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    # mode=ro URI ensures this handle refuses writes even if code tries.
    uri = f"file:{db_path.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    try:
        yield con
    finally:
        con.close()


def _row_to_finding(row: sqlite3.Row | tuple) -> FindingRow:
    (fingerprint, sink_type, file, line, severity, status,
     exclusion_category, payload_json, first_seen, last_seen) = row
    return FindingRow(
        fingerprint=fingerprint,
        status=status,
        severity=severity,
        sink_type=sink_type,
        file=file,
        line=line,
        exclusion_category=exclusion_category,
        first_seen=first_seen,
        last_seen=last_seen,
        payload=json.loads(payload_json) if payload_json else {},
    )


_BASE_COLS = (
    "fingerprint, sink_type, file, line, severity, status, "
    "exclusion_category, payload_json, first_seen, last_seen"
)


def list_findings(
    db_path: Path,
    *,
    status: str | None = None,
    severity: str | None = None,
    sink_type: str | None = None,
    q: str | None = None,
) -> list[FindingRow]:
    """List findings with optional filters. Sorted by severity asc, then last_seen desc."""
    where = []
    params: list[Any] = []
    if status:
        where.append("status = ?")
        params.append(status)
    if severity:
        where.append("UPPER(COALESCE(severity, '')) = ?")
        params.append(severity.upper())
    if sink_type:
        where.append("sink_type = ?")
        params.append(sink_type)
    if q:
        where.append("(file LIKE ? OR payload_json LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like])

    sql = f"SELECT {_BASE_COLS} FROM findings"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY last_seen DESC"

    with _connect(db_path) as con:
        rows = con.execute(sql, params).fetchall()
    findings = [_row_to_finding(r) for r in rows]
    findings.sort(key=lambda f: (f.severity_rank, -f.last_seen))
    return findings


def get_finding(db_path: Path, fingerprint: str) -> FindingRow | None:
    with _connect(db_path) as con:
        row = con.execute(
            f"SELECT {_BASE_COLS} FROM findings WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
    return _row_to_finding(row) if row else None


def distinct_sink_types(db_path: Path) -> list[str]:
    with _connect(db_path) as con:
        rows = con.execute(
            "SELECT DISTINCT sink_type FROM findings ORDER BY sink_type"
        ).fetchall()
    return [r[0] for r in rows if r[0]]


def severity_counts(db_path: Path) -> dict[str, int]:
    """Confirmed-only severity breakdown."""
    with _connect(db_path) as con:
        rows = con.execute(
            "SELECT UPPER(COALESCE(severity, 'MEDIUM')), COUNT(*) "
            "FROM findings WHERE status = 'confirmed' GROUP BY 1"
        ).fetchall()
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for sev, n in rows:
        out[sev] = out.get(sev, 0) + n
    return out


def sink_type_breakdown(db_path: Path) -> list[tuple[str, int]]:
    """Confirmed-only sink_type distribution, descending."""
    with _connect(db_path) as con:
        rows = con.execute(
            "SELECT sink_type, COUNT(*) FROM findings WHERE status = 'confirmed' "
            "GROUP BY sink_type ORDER BY 2 DESC"
        ).fetchall()
    return [(r[0], r[1]) for r in rows]


def weekly_trend(db_path: Path, weeks: int = 12) -> list[tuple[str, int]]:
    """(ISO week label, confirmed count first-seen that week) for the last N weeks."""
    with _connect(db_path) as con:
        rows = con.execute(
            "SELECT first_seen FROM findings WHERE status = 'confirmed'"
        ).fetchall()
    buckets: Counter[str] = Counter()
    for (first_seen,) in rows:
        label = time.strftime("%Y-W%V", time.gmtime(first_seen))
        buckets[label] += 1
    # last N weeks in chronological order; pad zeros where missing
    labels: list[str] = []
    seen: set[str] = set()
    for offset in range(weeks - 1, -1, -1):
        ts = time.time() - offset * 7 * 86400
        lb = time.strftime("%Y-W%V", time.gmtime(ts))
        if lb not in seen:
            seen.add(lb)
            labels.append(lb)
    return [(lb, buckets.get(lb, 0)) for lb in labels]


def db_mtime(db_path: Path) -> float:
    return db_path.stat().st_mtime
