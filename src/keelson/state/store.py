"""SQLite persistence for scans, findings, and events."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from keelson.core.models import (
    AgentCapability,
    AgentProfile,
    CampaignConfig,
    CampaignResult,
    Category,
    EvidenceItem,
    Finding,
    ProbeChain,
    ProbeStep,
    RegressionAlert,
    ScanResult,
    Severity,
    StatisticalFinding,
    Target,
    TrialResult,
    Verdict,
)

DEFAULT_DB_PATH = Path.home() / ".keelson" / "keelson.db"

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

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (target_url) REFERENCES targets(url)
);

CREATE TABLE IF NOT EXISTS statistical_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    owasp TEXT DEFAULT '',
    success_rate REAL DEFAULT 0.0,
    ci_lower REAL DEFAULT 0.0,
    ci_upper REAL DEFAULT 0.0,
    verdict TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
);

CREATE TABLE IF NOT EXISTS trials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    statistical_finding_id INTEGER NOT NULL,
    trial_index INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    reasoning TEXT DEFAULT '',
    response_time_ms INTEGER DEFAULT 0,
    FOREIGN KEY (statistical_finding_id) REFERENCES statistical_findings(id)
);

CREATE TABLE IF NOT EXISTS trial_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trial_id INTEGER NOT NULL,
    step_index INTEGER NOT NULL,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    response_time_ms INTEGER DEFAULT 0,
    FOREIGN KEY (trial_id) REFERENCES trials(id)
);

CREATE TABLE IF NOT EXISTS agent_profiles (
    profile_id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mutations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT,
    original_template_id TEXT NOT NULL,
    mutation_type TEXT NOT NULL,
    mutated_prompt TEXT NOT NULL,
    description TEXT DEFAULT '',
    verdict TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL UNIQUE,
    label TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS response_cache (
    cache_key TEXT PRIMARY KEY,
    messages_json TEXT NOT NULL,
    model TEXT NOT NULL,
    response_text TEXT NOT NULL,
    response_time_ms INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    hit_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS regression_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_a_id TEXT,
    scan_b_id TEXT,
    template_id TEXT NOT NULL,
    alert_severity TEXT NOT NULL,
    change_type TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS probe_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT UNIQUE NOT NULL,
    profile_id TEXT,
    name TEXT NOT NULL,
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    steps_json TEXT NOT NULL DEFAULT '[]',
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    owasp TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (profile_id) REFERENCES agent_profiles(profile_id)
);
"""


class Store:
    """SQLite store for Keelson scan data."""

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
                "INSERT INTO findings "
                "(scan_id, template_id, template_name, verdict, "
                "severity, category, owasp, reasoning, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    "INSERT INTO evidence "
                    "(finding_id, step_index, prompt, "
                    "response, response_time_ms) "
                    "VALUES (?, ?, ?, ?, ?)",
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
        finished = datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None
        return ScanResult(
            scan_id=scan_id,
            target=target,
            findings=findings,
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=finished,
        )

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
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
        findings: list[Finding] = []
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

    # --- Phase 2: Campaign persistence ---

    def save_campaign(self, campaign: CampaignResult) -> None:
        """Persist a complete campaign result."""
        c = self._conn
        # Upsert target
        c.execute(
            "INSERT OR REPLACE INTO targets (url, api_key, model, name) VALUES (?, ?, ?, ?)",
            (
                campaign.target.url,
                campaign.target.api_key,
                campaign.target.model,
                campaign.target.name,
            ),
        )
        c.execute(
            "INSERT INTO campaigns (campaign_id, target_url, config_json, started_at, finished_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                campaign.campaign_id,
                campaign.target.url,
                json.dumps(
                    {
                        "name": campaign.config.name,
                        "trials_per_probe": campaign.config.trials_per_probe,
                        "confidence_level": campaign.config.confidence_level,
                        "category": campaign.config.category,
                        "probe_ids": campaign.config.probe_ids,
                    }
                ),
                campaign.started_at.isoformat(),
                campaign.finished_at.isoformat() if campaign.finished_at else None,
            ),
        )
        for sf in campaign.findings:
            cursor = c.execute(
                "INSERT INTO statistical_findings "
                "(campaign_id, template_id, template_name, severity, category, owasp, "
                "success_rate, ci_lower, ci_upper, verdict) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    campaign.campaign_id,
                    sf.template_id,
                    sf.template_name,
                    sf.severity.value,
                    sf.category.value,
                    sf.owasp,
                    sf.success_rate,
                    sf.ci_lower,
                    sf.ci_upper,
                    sf.verdict.value,
                ),
            )
            sf_id = cursor.lastrowid
            for trial in sf.trials:
                tcursor = c.execute(
                    "INSERT INTO trials "
                    "(statistical_finding_id, trial_index, verdict, reasoning, response_time_ms) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        sf_id,
                        trial.trial_index,
                        trial.verdict.value,
                        trial.reasoning,
                        trial.response_time_ms,
                    ),
                )
                trial_id = tcursor.lastrowid
                for ev in trial.evidence:
                    c.execute(
                        "INSERT INTO trial_evidence "
                        "(trial_id, step_index, prompt, response, response_time_ms) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (trial_id, ev.step_index, ev.prompt, ev.response, ev.response_time_ms),
                    )
        self._log_event(
            "campaign_completed",
            {
                "campaign_id": campaign.campaign_id,
                "target": campaign.target.url,
            },
        )
        c.commit()

    def get_campaign(self, campaign_id: str) -> CampaignResult | None:
        """Load a campaign result by ID."""
        row = self._conn.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
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
        config_data = json.loads(row["config_json"])
        config = CampaignConfig(
            name=config_data.get("name", "default"),
            trials_per_probe=config_data.get("trials_per_probe", 5),
            confidence_level=config_data.get("confidence_level", 0.95),
            category=config_data.get("category"),
            probe_ids=config_data.get("probe_ids", []),
        )
        findings = self._load_statistical_findings(campaign_id)
        finished = datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None
        return CampaignResult(
            campaign_id=campaign_id,
            config=config,
            target=target,
            findings=findings,
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=finished,
        )

    def _load_statistical_findings(self, campaign_id: str) -> list[StatisticalFinding]:
        rows = self._conn.execute(
            "SELECT * FROM statistical_findings WHERE campaign_id = ? ORDER BY id",
            (campaign_id,),
        ).fetchall()
        findings: list[StatisticalFinding] = []
        for row in rows:
            trials = self._load_trials(row["id"])
            findings.append(
                StatisticalFinding(
                    template_id=row["template_id"],
                    template_name=row["template_name"],
                    severity=Severity(row["severity"]),
                    category=Category(row["category"]),
                    owasp=row["owasp"],
                    trials=trials,
                    success_rate=row["success_rate"],
                    ci_lower=row["ci_lower"],
                    ci_upper=row["ci_upper"],
                    verdict=Verdict(row["verdict"]),
                )
            )
        return findings

    def _load_trials(self, sf_id: int) -> list[TrialResult]:
        rows = self._conn.execute(
            "SELECT * FROM trials WHERE statistical_finding_id = ? ORDER BY trial_index",
            (sf_id,),
        ).fetchall()
        trials: list[TrialResult] = []
        for row in rows:
            ev_rows = self._conn.execute(
                "SELECT * FROM trial_evidence WHERE trial_id = ? ORDER BY step_index",
                (row["id"],),
            ).fetchall()
            evidence = [
                EvidenceItem(
                    step_index=er["step_index"],
                    prompt=er["prompt"],
                    response=er["response"],
                    response_time_ms=er["response_time_ms"],
                )
                for er in ev_rows
            ]
            trials.append(
                TrialResult(
                    trial_index=row["trial_index"],
                    verdict=Verdict(row["verdict"]),
                    evidence=evidence,
                    reasoning=row["reasoning"],
                    response_time_ms=row["response_time_ms"],
                )
            )
        return trials

    def list_campaigns(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent campaigns."""
        rows = self._conn.execute(
            "SELECT c.campaign_id, c.target_url, c.started_at, c.finished_at, "
            "COUNT(sf.id) as total_probes, "
            "SUM(CASE WHEN sf.verdict = 'VULNERABLE' THEN 1 ELSE 0 END) as vulnerable "
            "FROM campaigns c LEFT JOIN statistical_findings sf ON c.campaign_id = sf.campaign_id "
            "GROUP BY c.campaign_id ORDER BY c.started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Phase 2: Agent profile persistence ---

    def save_agent_profile(self, profile: AgentProfile) -> None:
        """Persist an agent capability profile."""
        self._conn.execute(
            "INSERT OR REPLACE INTO agent_profiles "
            "(profile_id, target_url, "
            "capabilities_json, created_at) "
            "VALUES (?, ?, ?, ?)",
            (
                profile.profile_id,
                profile.target_url,
                json.dumps(
                    [
                        {
                            "name": c.name,
                            "detected": c.detected,
                            "probe_prompt": c.probe_prompt,
                            "response_excerpt": c.response_excerpt,
                            "confidence": c.confidence,
                        }
                        for c in profile.capabilities
                    ]
                ),
                profile.created_at.isoformat(),
            ),
        )
        self._log_event(
            "profile_saved",
            {
                "profile_id": profile.profile_id,
                "target": profile.target_url,
            },
        )
        self._conn.commit()

    def get_agent_profile(self, profile_id: str) -> AgentProfile | None:
        """Load an agent profile by ID."""
        row = self._conn.execute(
            "SELECT * FROM agent_profiles WHERE profile_id = ?", (profile_id,)
        ).fetchone()
        if not row:
            return None
        caps_data = json.loads(row["capabilities_json"])
        caps = [
            AgentCapability(
                name=c["name"],
                detected=c["detected"],
                probe_prompt=c["probe_prompt"],
                response_excerpt=c.get("response_excerpt", ""),
                confidence=c.get("confidence", 0.0),
            )
            for c in caps_data
        ]
        return AgentProfile(
            profile_id=profile_id,
            target_url=row["target_url"],
            capabilities=caps,
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # --- Phase 2: Baseline persistence ---

    def save_baseline(self, scan_id: str, label: str = "") -> None:
        """Mark a scan as a regression baseline."""
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_baselines (scan_id, label, created_at) VALUES (?, ?, ?)",
            (scan_id, label, datetime.now(UTC).isoformat()),
        )
        self._log_event("baseline_set", {"scan_id": scan_id, "label": label})
        self._conn.commit()

    def get_baselines(self, limit: int = 20) -> list[dict[str, Any]]:
        """List scan baselines."""
        rows = self._conn.execute(
            "SELECT b.scan_id, b.label, b.created_at, s.target_url "
            "FROM scan_baselines b JOIN scans s ON b.scan_id = s.scan_id "
            "ORDER BY b.created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Phase 3: Response cache persistence ---

    def save_cache_entry(
        self,
        cache_key: str,
        messages: list[dict[str, Any]],
        model: str,
        response_text: str,
        response_time_ms: int,
    ) -> None:
        """Save a response to the persistent cache."""
        self._conn.execute(
            "INSERT OR REPLACE INTO response_cache "
            "(cache_key, messages_json, model, "
            "response_text, response_time_ms, "
            "created_at, hit_count) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (
                cache_key,
                json.dumps(messages),
                model,
                response_text,
                response_time_ms,
                datetime.now(UTC).isoformat(),
            ),
        )
        self._conn.commit()

    def get_cache_entry(self, cache_key: str) -> dict[str, Any] | None:
        """Load a cached response by key."""
        row = self._conn.execute(
            "SELECT * FROM response_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
        if not row:
            return None
        # Increment hit count
        self._conn.execute(
            "UPDATE response_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
            (cache_key,),
        )
        self._conn.commit()
        return dict(row)

    # --- Phase 3: Regression alerts persistence ---

    def save_regression_alerts(
        self,
        scan_a_id: str,
        scan_b_id: str,
        alerts: list[RegressionAlert],
    ) -> None:
        """Persist regression alerts from a scan diff."""
        for alert in alerts:
            self._conn.execute(
                "INSERT INTO regression_alerts "
                "(scan_a_id, scan_b_id, template_id, "
                "alert_severity, change_type, "
                "description, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_a_id,
                    scan_b_id,
                    alert.template_id,
                    alert.alert_severity,
                    alert.change_type,
                    alert.description,
                    datetime.now(UTC).isoformat(),
                ),
            )
        self._log_event(
            "regression_alerts_saved",
            {
                "scan_a_id": scan_a_id,
                "scan_b_id": scan_b_id,
                "count": len(alerts),
            },
        )
        self._conn.commit()

    def list_regression_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recent regression alerts."""
        rows = self._conn.execute(
            "SELECT * FROM regression_alerts ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        """Mark a regression alert as acknowledged."""
        self._conn.execute(
            "UPDATE regression_alerts SET acknowledged = 1 WHERE id = ?",
            (alert_id,),
        )
        self._conn.commit()

    # --- Phase 3: Probe chain persistence ---

    def save_probe_chain(self, chain: ProbeChain, profile_id: str | None = None) -> None:
        """Persist an probe chain."""
        self._conn.execute(
            "INSERT OR REPLACE INTO probe_chains "
            "(chain_id, profile_id, name, "
            "capabilities_json, steps_json, severity, "
            "category, owasp, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                chain.chain_id,
                profile_id,
                chain.name,
                json.dumps(chain.capabilities),
                json.dumps(
                    [
                        {"index": s.index, "prompt": s.prompt, "is_followup": s.is_followup}
                        for s in chain.steps
                    ]
                ),
                chain.severity.value,
                chain.category.value,
                chain.owasp,
                datetime.now(UTC).isoformat(),
            ),
        )
        self._log_event("probe_chain_saved", {"chain_id": chain.chain_id, "name": chain.name})
        self._conn.commit()

    def get_probe_chain(self, chain_id: str) -> ProbeChain | None:
        """Load an probe chain by ID."""
        row = self._conn.execute(
            "SELECT * FROM probe_chains WHERE chain_id = ?", (chain_id,)
        ).fetchone()
        if not row:
            return None
        steps_data = json.loads(row["steps_json"])
        steps = [
            ProbeStep(index=s["index"], prompt=s["prompt"], is_followup=s.get("is_followup", False))
            for s in steps_data
        ]
        return ProbeChain(
            chain_id=row["chain_id"],
            name=row["name"],
            capabilities=json.loads(row["capabilities_json"]),
            steps=steps,
            severity=Severity(row["severity"]),
            category=Category(row["category"]),
            owasp=row["owasp"],
        )

    def list_probe_chains(
        self, profile_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List probe chains, optionally filtered by profile."""
        if profile_id:
            rows = self._conn.execute(
                "SELECT * FROM probe_chains WHERE profile_id = ? ORDER BY created_at DESC LIMIT ?",
                (profile_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM probe_chains ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def _log_event(self, event_type: str, data: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO events (timestamp, event_type, data) VALUES (?, ?, ?)",
            (datetime.now(UTC).isoformat(), event_type, json.dumps(data)),
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
