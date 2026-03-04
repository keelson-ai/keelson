"""SQLite persistence for scans, findings, and events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pentis.core.models import (
    AgentCapability,
    AgentProfile,
    AttackChain,
    AttackStep,
    CampaignConfig,
    CampaignResult,
    Category,
    EvidenceItem,
    Finding,
    LearningRecord,
    RegressionAlert,
    ScanJob,
    ScanResult,
    ScanStatus,
    ScheduleConfig,
    Severity,
    StatisticalFinding,
    Target,
    TargetHealthStatus,
    TrialResult,
    Verdict,
    WebhookConfig,
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

CREATE TABLE IF NOT EXISTS attack_chains (
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

CREATE TABLE IF NOT EXISTS schedules (
    schedule_id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    api_key TEXT DEFAULT '',
    adapter_type TEXT DEFAULT 'openai',
    tier TEXT DEFAULT 'deep',
    interval_seconds INTEGER DEFAULT 21600,
    enabled INTEGER DEFAULT 1,
    category TEXT,
    attacker_api_key TEXT DEFAULT '',
    attacker_model TEXT DEFAULT 'default',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    scan_id TEXT PRIMARY KEY,
    schedule_id TEXT,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INTEGER DEFAULT 0,
    total_attacks INTEGER DEFAULT 0,
    vulnerable_count INTEGER DEFAULT 0,
    error_message TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    events_json TEXT NOT NULL DEFAULT '[]',
    secret TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_health (
    target_url TEXT PRIMARY KEY,
    healthy INTEGER DEFAULT 1,
    consecutive_failures INTEGER DEFAULT 0,
    last_check_at TEXT,
    last_response_time_ms INTEGER DEFAULT 0,
    last_error TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS learning_records (
    record_id TEXT PRIMARY KEY,
    cycle_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    attacks_run INTEGER DEFAULT 0,
    vulns_found INTEGER DEFAULT 0,
    defense_patterns_json TEXT NOT NULL DEFAULT '[]',
    successful_mutations_json TEXT NOT NULL DEFAULT '[]',
    coverage_gaps_json TEXT NOT NULL DEFAULT '[]',
    strategy_weights_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
"""


class Store:
    """SQLite store for Pentis scan data."""

    def __init__(self, db_path: Path | None = None, check_same_thread: bool = True):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=check_same_thread)
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
                        "trials_per_attack": campaign.config.trials_per_attack,
                        "confidence_level": campaign.config.confidence_level,
                        "category": campaign.config.category,
                        "attack_ids": campaign.config.attack_ids,
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
            trials_per_attack=config_data.get("trials_per_attack", 5),
            confidence_level=config_data.get("confidence_level", 0.95),
            category=config_data.get("category"),
            attack_ids=config_data.get("attack_ids", []),
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
            "COUNT(sf.id) as total_attacks, "
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
            "INSERT OR REPLACE INTO agent_profiles (profile_id, target_url, capabilities_json, created_at) "
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
            (scan_id, label, datetime.now(timezone.utc).isoformat()),
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
            "(cache_key, messages_json, model, response_text, response_time_ms, created_at, hit_count) "
            "VALUES (?, ?, ?, ?, ?, ?, 0)",
            (
                cache_key,
                json.dumps(messages),
                model,
                response_text,
                response_time_ms,
                datetime.now(timezone.utc).isoformat(),
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
                "(scan_a_id, scan_b_id, template_id, alert_severity, change_type, description, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_a_id,
                    scan_b_id,
                    alert.template_id,
                    alert.alert_severity,
                    alert.change_type,
                    alert.description,
                    datetime.now(timezone.utc).isoformat(),
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

    # --- Phase 3: Attack chain persistence ---

    def save_attack_chain(self, chain: AttackChain, profile_id: str | None = None) -> None:
        """Persist an attack chain."""
        self._conn.execute(
            "INSERT OR REPLACE INTO attack_chains "
            "(chain_id, profile_id, name, capabilities_json, steps_json, severity, category, owasp, created_at) "
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
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._log_event("attack_chain_saved", {"chain_id": chain.chain_id, "name": chain.name})
        self._conn.commit()

    def get_attack_chain(self, chain_id: str) -> AttackChain | None:
        """Load an attack chain by ID."""
        row = self._conn.execute(
            "SELECT * FROM attack_chains WHERE chain_id = ?", (chain_id,)
        ).fetchone()
        if not row:
            return None
        steps_data = json.loads(row["steps_json"])
        steps = [
            AttackStep(
                index=s["index"], prompt=s["prompt"], is_followup=s.get("is_followup", False)
            )
            for s in steps_data
        ]
        return AttackChain(
            chain_id=row["chain_id"],
            name=row["name"],
            capabilities=json.loads(row["capabilities_json"]),
            steps=steps,
            severity=Severity(row["severity"]),
            category=Category(row["category"]),
            owasp=row["owasp"],
        )

    def list_attack_chains(
        self, profile_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List attack chains, optionally filtered by profile."""
        if profile_id:
            rows = self._conn.execute(
                "SELECT * FROM attack_chains WHERE profile_id = ? ORDER BY created_at DESC LIMIT ?",
                (profile_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM attack_chains ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # --- Service Layer: Schedule persistence ---

    def save_schedule(self, schedule: ScheduleConfig) -> None:
        """Persist a schedule configuration."""
        self._conn.execute(
            "INSERT OR REPLACE INTO schedules "
            "(schedule_id, target_url, api_key, adapter_type, tier, interval_seconds, "
            "enabled, category, attacker_api_key, attacker_model, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                schedule.schedule_id,
                schedule.target_url,
                schedule.api_key,
                schedule.adapter_type,
                schedule.tier,
                schedule.interval_seconds,
                1 if schedule.enabled else 0,
                schedule.category,
                schedule.attacker_api_key,
                schedule.attacker_model,
                schedule.created_at.isoformat(),
            ),
        )
        self._log_event("schedule_saved", {"schedule_id": schedule.schedule_id})
        self._conn.commit()

    def get_schedule(self, schedule_id: str) -> ScheduleConfig | None:
        """Load a schedule by ID."""
        row = self._conn.execute(
            "SELECT * FROM schedules WHERE schedule_id = ?", (schedule_id,)
        ).fetchone()
        if not row:
            return None
        return ScheduleConfig(
            schedule_id=row["schedule_id"],
            target_url=row["target_url"],
            api_key=row["api_key"],
            adapter_type=row["adapter_type"],
            tier=row["tier"],
            interval_seconds=row["interval_seconds"],
            enabled=bool(row["enabled"]),
            category=row["category"],
            attacker_api_key=row["attacker_api_key"],
            attacker_model=row["attacker_model"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def list_schedules(self, limit: int = 50) -> list[dict[str, Any]]:
        """List all schedules."""
        rows = self._conn.execute(
            "SELECT * FROM schedules ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule. Returns True if deleted."""
        cursor = self._conn.execute(
            "DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # --- Service Layer: Scan job persistence ---

    def save_scan_job(self, job: ScanJob) -> None:
        """Persist a scan job."""
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_jobs "
            "(scan_id, schedule_id, target_url, status, progress, total_attacks, "
            "vulnerable_count, error_message, created_at, started_at, finished_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                job.scan_id,
                job.schedule_id,
                job.target_url,
                job.status.value,
                job.progress,
                job.total_attacks,
                job.vulnerable_count,
                job.error_message,
                job.created_at.isoformat(),
                job.started_at.isoformat() if job.started_at else None,
                job.finished_at.isoformat() if job.finished_at else None,
            ),
        )
        self._conn.commit()

    def get_scan_job(self, scan_id: str) -> ScanJob | None:
        """Load a scan job by ID."""
        row = self._conn.execute(
            "SELECT * FROM scan_jobs WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        return ScanJob(
            scan_id=row["scan_id"],
            schedule_id=row["schedule_id"],
            target_url=row["target_url"],
            status=ScanStatus(row["status"]),
            progress=row["progress"],
            total_attacks=row["total_attacks"],
            vulnerable_count=row["vulnerable_count"],
            error_message=row["error_message"],
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            finished_at=(
                datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None
            ),
        )

    def list_scan_jobs(
        self, status: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List scan jobs, optionally filtered by status."""
        if status:
            rows = self._conn.execute(
                "SELECT * FROM scan_jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def update_scan_job_status(
        self,
        scan_id: str,
        status: ScanStatus,
        progress: int | None = None,
        vulnerable_count: int | None = None,
        error_message: str | None = None,
    ) -> None:
        """Update a scan job's status and optional fields."""
        updates = ["status = ?"]
        params: list[Any] = [status.value]
        if progress is not None:
            updates.append("progress = ?")
            params.append(progress)
        if vulnerable_count is not None:
            updates.append("vulnerable_count = ?")
            params.append(vulnerable_count)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if status == ScanStatus.RUNNING:
            updates.append("started_at = ?")
            params.append(datetime.now(timezone.utc).isoformat())
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            updates.append("finished_at = ?")
            params.append(datetime.now(timezone.utc).isoformat())
        params.append(scan_id)
        self._conn.execute(
            f"UPDATE scan_jobs SET {', '.join(updates)} WHERE scan_id = ?", params
        )
        self._conn.commit()

    # --- Service Layer: Webhook persistence ---

    def save_webhook(self, webhook: WebhookConfig) -> None:
        """Persist a webhook configuration."""
        self._conn.execute(
            "INSERT OR REPLACE INTO webhooks "
            "(webhook_id, url, events_json, secret, enabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                webhook.webhook_id,
                webhook.url,
                json.dumps(webhook.events),
                webhook.secret,
                1 if webhook.enabled else 0,
                webhook.created_at.isoformat(),
            ),
        )
        self._conn.commit()

    def list_webhooks(self) -> list[WebhookConfig]:
        """List all webhooks."""
        rows = self._conn.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
        return [
            WebhookConfig(
                webhook_id=r["webhook_id"],
                url=r["url"],
                events=json.loads(r["events_json"]),
                secret=r["secret"],
                enabled=bool(r["enabled"]),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]

    def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook. Returns True if deleted."""
        cursor = self._conn.execute(
            "DELETE FROM webhooks WHERE webhook_id = ?", (webhook_id,)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    # --- Service Layer: Target health persistence ---

    def save_target_health(self, health: TargetHealthStatus) -> None:
        """Persist target health status."""
        self._conn.execute(
            "INSERT OR REPLACE INTO target_health "
            "(target_url, healthy, consecutive_failures, last_check_at, "
            "last_response_time_ms, last_error) VALUES (?, ?, ?, ?, ?, ?)",
            (
                health.target_url,
                1 if health.healthy else 0,
                health.consecutive_failures,
                health.last_check_at.isoformat() if health.last_check_at else None,
                health.last_response_time_ms,
                health.last_error,
            ),
        )
        self._conn.commit()

    def get_target_health(self, target_url: str) -> TargetHealthStatus | None:
        """Load target health status."""
        row = self._conn.execute(
            "SELECT * FROM target_health WHERE target_url = ?", (target_url,)
        ).fetchone()
        if not row:
            return None
        return TargetHealthStatus(
            target_url=row["target_url"],
            healthy=bool(row["healthy"]),
            consecutive_failures=row["consecutive_failures"],
            last_check_at=(
                datetime.fromisoformat(row["last_check_at"]) if row["last_check_at"] else None
            ),
            last_response_time_ms=row["last_response_time_ms"],
            last_error=row["last_error"],
        )

    def list_target_health(self) -> list[TargetHealthStatus]:
        """List all target health statuses."""
        rows = self._conn.execute("SELECT * FROM target_health").fetchall()
        return [
            TargetHealthStatus(
                target_url=r["target_url"],
                healthy=bool(r["healthy"]),
                consecutive_failures=r["consecutive_failures"],
                last_check_at=(
                    datetime.fromisoformat(r["last_check_at"]) if r["last_check_at"] else None
                ),
                last_response_time_ms=r["last_response_time_ms"],
                last_error=r["last_error"],
            )
            for r in rows
        ]

    # --- Service Layer: Learning record persistence ---

    def save_learning_record(self, record: LearningRecord) -> None:
        """Persist a learning record from a red team cycle."""
        self._conn.execute(
            "INSERT OR REPLACE INTO learning_records "
            "(record_id, cycle_id, target_url, attacks_run, vulns_found, "
            "defense_patterns_json, successful_mutations_json, coverage_gaps_json, "
            "strategy_weights_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.record_id,
                record.cycle_id,
                record.target_url,
                record.attacks_run,
                record.vulns_found,
                json.dumps(record.defense_patterns),
                json.dumps(record.successful_mutations),
                json.dumps(record.coverage_gaps),
                json.dumps(record.strategy_weights),
                record.created_at.isoformat(),
            ),
        )
        self._log_event(
            "learning_record_saved",
            {"record_id": record.record_id, "target": record.target_url},
        )
        self._conn.commit()

    def list_learning_records(
        self, target_url: str | None = None, limit: int = 50
    ) -> list[LearningRecord]:
        """List learning records, optionally filtered by target."""
        if target_url:
            rows = self._conn.execute(
                "SELECT * FROM learning_records WHERE target_url = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (target_url, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM learning_records ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            LearningRecord(
                record_id=r["record_id"],
                cycle_id=r["cycle_id"],
                target_url=r["target_url"],
                attacks_run=r["attacks_run"],
                vulns_found=r["vulns_found"],
                defense_patterns=json.loads(r["defense_patterns_json"]),
                successful_mutations=json.loads(r["successful_mutations_json"]),
                coverage_gaps=json.loads(r["coverage_gaps_json"]),
                strategy_weights=json.loads(r["strategy_weights_json"]),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]

    def get_latest_learning_record(self, target_url: str) -> LearningRecord | None:
        """Get the most recent learning record for a target."""
        records = self.list_learning_records(target_url=target_url, limit=1)
        return records[0] if records else None

    def _log_event(self, event_type: str, data: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO events (timestamp, event_type, data) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), event_type, json.dumps(data)),
        )

    def close(self) -> None:
        self._conn.close()
