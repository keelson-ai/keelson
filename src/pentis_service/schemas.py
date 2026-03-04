"""Pydantic request/response schemas for the Pentis service API."""

from __future__ import annotations

from pydantic import BaseModel, Field


# --- Scan schemas ---


class ScanRequest(BaseModel):
    target_url: str
    api_key: str = ""
    model: str = "default"
    adapter_type: str = "openai"
    category: str | None = None
    tier: str = "deep"
    delay: float = 1.5


class ScanJobResponse(BaseModel):
    scan_id: str
    schedule_id: str | None = None
    target_url: str
    status: str
    progress: int = 0
    total_attacks: int = 0
    vulnerable_count: int = 0
    error_message: str = ""
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None


class FindingResponse(BaseModel):
    template_id: str
    template_name: str
    verdict: str
    severity: str
    category: str
    owasp: str = ""
    reasoning: str = ""
    evidence: list[EvidenceResponse] = []


class EvidenceResponse(BaseModel):
    step_index: int
    prompt: str
    response: str
    response_time_ms: int = 0


# Rebuild FindingResponse to pick up forward ref
FindingResponse.model_rebuild()


# --- Schedule schemas ---


class ScheduleRequest(BaseModel):
    target_url: str
    api_key: str = ""
    adapter_type: str = "openai"
    tier: str = "deep"
    interval_seconds: int = Field(default=21600, ge=300)
    category: str | None = None
    attacker_api_key: str = ""
    attacker_model: str = "default"


class ScheduleResponse(BaseModel):
    schedule_id: str
    target_url: str
    adapter_type: str
    tier: str
    interval_seconds: int
    enabled: bool
    category: str | None = None
    created_at: str


# --- Webhook schemas ---


class WebhookRequest(BaseModel):
    url: str
    events: list[str] = Field(default_factory=list)
    secret: str = ""


class WebhookResponse(BaseModel):
    webhook_id: str
    url: str
    events: list[str]
    enabled: bool
    created_at: str


# --- Alert schemas ---


class AlertResponse(BaseModel):
    id: int
    scan_a_id: str | None = None
    scan_b_id: str | None = None
    template_id: str
    alert_severity: str
    change_type: str
    description: str = ""
    created_at: str
    acknowledged: bool = False


# --- Dashboard schemas ---


class DashboardResponse(BaseModel):
    total_scans: int = 0
    total_vulnerabilities: int = 0
    active_schedules: int = 0
    targets_monitored: int = 0
    target_health: list[TargetHealthResponse] = []
    recent_scans: list[ScanJobResponse] = []
    learning_summary: LearningSummaryResponse | None = None


class TargetHealthResponse(BaseModel):
    target_url: str
    healthy: bool
    consecutive_failures: int = 0
    last_check_at: str | None = None
    last_response_time_ms: int = 0


class LearningSummaryResponse(BaseModel):
    total_cycles: int = 0
    total_attacks_run: int = 0
    total_vulns_found: int = 0
    top_defense_patterns: list[str] = []
    top_successful_mutations: list[str] = []


# Rebuild models with forward refs
DashboardResponse.model_rebuild()


# --- Onboard schemas ---


class OnboardRequest(BaseModel):
    target_url: str
    api_key: str = ""
    adapter_type: str = "openai"
    attacker_api_key: str = ""
    attacker_model: str = "default"
    run_mode: str = "continuous"
    interval_seconds: int = Field(default=21600, ge=300)
    webhook_url: str = ""


class OnboardResponse(BaseModel):
    healthy: bool
    response_time_ms: int = 0
    capabilities: list[CapabilityResponse] = []
    attack_plan: AttackPlanResponse | None = None
    schedule_id: str | None = None


class CapabilityResponse(BaseModel):
    name: str
    detected: bool
    confidence: float = 0.0


class AttackPlanResponse(BaseModel):
    playbook_attacks: int = 0
    capability_attacks: int = 0
    chain_attacks: int = 0


# Rebuild
OnboardResponse.model_rebuild()


# --- Event schemas ---


class EventResponse(BaseModel):
    event_type: str
    data: dict[str, object] = {}
    timestamp: str


# --- Report schemas ---


class ReportRequest(BaseModel):
    format: str = "markdown"  # markdown, sarif, junit
