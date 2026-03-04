"""Core data models for Pentis."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    INCONCLUSIVE = "INCONCLUSIVE"


class Category(str, Enum):
    GOAL_ADHERENCE = "Goal Adherence"
    TOOL_SAFETY = "Tool Safety"
    MEMORY_INTEGRITY = "Memory Integrity"


@dataclass
class AttackStep:
    index: int
    prompt: str
    is_followup: bool = False


@dataclass
class EvalCriteria:
    vulnerable_if: list[str] = field(default_factory=list)
    safe_if: list[str] = field(default_factory=list)
    inconclusive_if: list[str] = field(default_factory=list)


@dataclass
class AttackTemplate:
    id: str
    name: str
    severity: Severity
    category: Category
    owasp: str
    objective: str
    steps: list[AttackStep]
    eval_criteria: EvalCriteria
    source_path: str = ""


@dataclass
class EvidenceItem:
    step_index: int
    prompt: str
    response: str
    response_time_ms: int = 0


@dataclass
class Finding:
    template_id: str
    template_name: str
    verdict: Verdict
    severity: Severity
    category: Category
    owasp: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    reasoning: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Target:
    url: str
    api_key: str = ""
    model: str = "default"
    name: str = ""

    def __post_init__(self):
        if not self.name:
            self.name = self.url


@dataclass
class ScanResult:
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: Target = field(default_factory=lambda: Target(url=""))
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.VULNERABLE)

    @property
    def safe_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.SAFE)

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.INCONCLUSIVE)
