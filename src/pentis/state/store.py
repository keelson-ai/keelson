"""SQLite persistence for scans, findings, and events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from pentis.core.models import (
    Category,
    EvidenceItem,
    Finding,
    ScanResult,
    Severity,
    Target,
    Verdict,
)

DEFAULT_DB_PATH = Path.home() / ".pentis" / "pentis.db"

SCHEMA = """\
CREATE TABLE IF NOT EXISTS targets (
    url TEXT PRIMARY KEY,
    api_key TEXT DEFAULT '',
    model TEXT DEFAULT 'default',
    name TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (target_url) REFERENCES targets(url)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_name TEXT NOT NULL,
    verdict TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    owasp TEXT DEFAULT '',
    reasoning TEXT DEFAULT '',
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    step_index INTEGER NOT NULL,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    response_time_ms INTEGER DEFAULT 0,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    data TEXT DEFAULT '{}'
);
"""


class Store:
    """SQLite store for Pentis scan data."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def save_scan(self, scan: ScanResult) -> None:
        """Persist a complete scan result."""
        c = self._conn
        # Upsert target
        c.execute(
            "INSERT OR REPLACE INTO targets (url, api_key, model, name) VALUES (?, ?, ?, ?)",
            (scan.target.url, scan.target.api_key, scan.target.model, scan.target.name),
        )
        # Insert scan
        c.execute(
            "INSERT INTO scans (scan_id, target_url, started_at, finished_at) VALUES (?, ?, ?, ?)",
            (
                scan.scan_id,
                scan.target.url,
                scan.started_at.isoformat(),
                scan.finished_at.isoformat() if scan.finished_at else None,
            ),
        )
        # Insert findings and evidence
        for finding in scan.findings:
            cursor = c.execute(
                "INSERT INTO findings (scan_id, template_id, template_name, verdict, severity, category, owasp, reasoning, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan.scan_id,
                    finding.template_id,
                    finding.template_name,
                    finding.verdict.value,
                    finding.severity.value,
                    finding.category.value,
                    finding.owasp,
                    finding.reasoning,
                    finding.timestamp.isoformat(),
                ),
            )
            finding_id = cursor.lastrowid
            for ev in finding.evidence:
                c.execute(
                    "INSERT INTO evidence (finding_id, step_index, prompt, response, response_time_ms) VALUES (?, ?, ?, ?, ?)",
                    (finding_id, ev.step_index, ev.prompt, ev.response, ev.response_time_ms),
                )
        # Audit event
        self._log_event("scan_completed", {"scan_id": scan.scan_id, "target": scan.target.url})
        c.commit()

    def get_scan(self, scan_id: str) -> ScanResult | None:
        """Load a scan result by ID."""
        row = self._conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        target_row = self._conn.execute(
            "SELECT * FROM targets WHERE url = ?", (row["target_url"],)
        ).fetchone()
        target = Target(
            url=target_row["url"],
            api_key=target_row["api_key"],
            model=target_row["model"],
            name=target_row["name"],
        )
        findings = self._load_findings(scan_id)
        finished = (
            datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None
        )
        return ScanResult(
            scan_id=scan_id,
            target=target,
            findings=findings,
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=finished,
        )

    def list_scans(self, limit: int = 20) -> list[dict]:
        """List recent scans with summary info."""
        rows = self._conn.execute(
            "SELECT s.scan_id, s.target_url, s.started_at, s.finished_at, "
            "COUNT(f.id) as total, "
            "SUM(CASE WHEN f.verdict = 'VULNERABLE' THEN 1 ELSE 0 END) as vulnerable, "
            "SUM(CASE WHEN f.verdict = 'SAFE' THEN 1 ELSE 0 END) as safe "
            "FROM scans s LEFT JOIN findings f ON s.scan_id = f.scan_id "
            "GROUP BY s.scan_id ORDER BY s.started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def _load_findings(self, scan_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        findings = []
        for row in rows:
            evidence_rows = self._conn.execute(
                "SELECT * FROM evidence WHERE finding_id = ? ORDER BY step_index", (row["id"],)
            ).fetchall()
            evidence = [
                EvidenceItem(
                    step_index=er["step_index"],
                    prompt=er["prompt"],
                    response=er["response"],
                    response_time_ms=er["response_time_ms"],
                )
                for er in evidence_rows
            ]
            findings.append(
                Finding(
                    template_id=row["template_id"],
                    template_name=row["template_name"],
                    verdict=Verdict(row["verdict"]),
                    severity=Severity(row["severity"]),
                    category=Category(row["category"]),
                    owasp=row["owasp"],
                    evidence=evidence,
                    reasoning=row["reasoning"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                )
            )
        return findings

    def _log_event(self, event_type: str, data: dict) -> None:
        self._conn.execute(
            "INSERT INTO events (timestamp, event_type, data) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), event_type, json.dumps(data)),
        )

    def close(self) -> None:
        self._conn.close()
