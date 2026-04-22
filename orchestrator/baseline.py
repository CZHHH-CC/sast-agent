"""SQLite-backed baseline of findings for dedup and re-scan skipping."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    sink_type TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER,
    severity TEXT,
    status TEXT NOT NULL,               -- confirmed | excluded
    exclusion_category TEXT,
    payload_json TEXT NOT NULL,          -- full validator output
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_llm_check_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file);
"""


class Baseline:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.db_path)
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def get(self, fingerprint: str) -> dict | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT payload_json, status, last_llm_check_at "
                "FROM findings WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        if not row:
            return None
        return {
            "payload": json.loads(row[0]),
            "status": row[1],
            "last_llm_check_at": row[2],
        }

    def upsert(self, fingerprint: str, finding: dict) -> None:
        now = time.time()
        status = finding.get("status", "confirmed")
        with self._connect() as con:
            existing = con.execute(
                "SELECT first_seen FROM findings WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            first_seen = existing[0] if existing else now
            con.execute(
                """
                INSERT INTO findings (
                    fingerprint, sink_type, file, line, severity,
                    status, exclusion_category, payload_json,
                    first_seen, last_seen, last_llm_check_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    status=excluded.status,
                    severity=excluded.severity,
                    exclusion_category=excluded.exclusion_category,
                    payload_json=excluded.payload_json,
                    last_seen=excluded.last_seen,
                    last_llm_check_at=excluded.last_llm_check_at
                """,
                (
                    fingerprint,
                    finding.get("sink_type", ""),
                    finding.get("file", ""),
                    finding.get("line"),
                    finding.get("severity"),
                    status,
                    finding.get("exclusion_category"),
                    json.dumps(finding, ensure_ascii=False),
                    first_seen,
                    now,
                    now,
                ),
            )

    def all_confirmed(self) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT payload_json FROM findings WHERE status = 'confirmed'"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def all_excluded(self) -> list[dict]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT payload_json FROM findings WHERE status = 'excluded'"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]
