"""Core data models for Pentis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class Behavior(str, Enum):
    GOAL_ADHERENCE = "goal_adherence"
    TOOL_SAFETY = "tool_safety"
    MEMORY_INTEGRITY = "memory_integrity"


@dataclass
class AgentResponse:
    """Response from an AI agent endpoint."""

    content: str
    raw: dict[str, Any] = field(default_factory=dict)
    model: str = ""
    finish_reason: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    latency_ms: float = 0.0

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


@dataclass
class TargetInfo:
    """Information discovered about the target agent."""

    url: str
    model: str = ""
    system_prompt_leaked: str = ""
    tools_detected: list[str] = field(default_factory=list)
    supports_tools: bool = False
    supports_history: bool = True
    response_format: str = "openai"


@dataclass
class AttackTemplate:
    """A loaded attack template."""

    id: str
    name: str
    behavior: str
    severity: str
    description: str
    owasp_id: str | None = None
    owasp_name: str | None = None
    steps: list[AttackStep] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackStep:
    """A single step in an attack template."""

    role: str  # "user" or "system"
    content: str
    expect_refusal: bool = False
    reset_history: bool = False


@dataclass
class Indicator:
    """Detection indicator for a template."""

    type: str  # "word", "regex", "absence"
    value: str
    weight: float = 1.0


@dataclass
class Finding:
    """A single vulnerability finding."""

    template_id: str
    template_name: str
    behavior: str
    severity: str
    status: FindingStatus
    owasp_id: str | None = None
    owasp_name: str | None = None
    description: str = ""
    evidence: list[EvidenceItem] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return self.status == FindingStatus.VULNERABLE


@dataclass
class EvidenceItem:
    """Evidence from a single attack step."""

    step_index: int
    prompt: str
    response: str
    indicators_matched: list[str] = field(default_factory=list)
    refusal_detected: bool = False


@dataclass
class ScanResult:
    """Complete scan result."""

    target: TargetInfo
    findings: list[Finding] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    templates_run: int = 0
    templates_total: int = 0

    @property
    def duration_seconds(self) -> float:
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.is_vulnerable)

    @property
    def safe_count(self) -> int:
        return sum(1 for f in self.findings if f.status == FindingStatus.SAFE)

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for f in self.findings if f.status == FindingStatus.INCONCLUSIVE)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.status == FindingStatus.ERROR)

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    def findings_by_behavior(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.behavior, []).append(f)
        return result
