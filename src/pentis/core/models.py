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


class MutationType(str, Enum):
    """Types of prompt mutations."""
    BASE64_ENCODE = "base64_encode"
    LEETSPEAK = "leetspeak"
    CONTEXT_OVERFLOW = "context_overflow"
    PARAPHRASE = "paraphrase"
    ROLEPLAY_WRAP = "roleplay_wrap"
    GRADUAL_ESCALATION = "gradual_escalation"


class ResponseClass(str, Enum):
    """Classification of a target response for branching."""
    REFUSAL = "refusal"
    PARTIAL = "partial"
    COMPLIANCE = "compliance"


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


# --- Phase 2 Models ---


@dataclass
class TrialResult:
    """Single trial execution of an attack."""
    trial_index: int
    verdict: Verdict
    evidence: list[EvidenceItem] = field(default_factory=list)
    reasoning: str = ""
    response_time_ms: int = 0


@dataclass
class StatisticalFinding:
    """Aggregated result over N trials for a single attack."""
    template_id: str
    template_name: str
    severity: Severity
    category: Category
    owasp: str
    trials: list[TrialResult] = field(default_factory=list)
    success_rate: float = 0.0
    ci_lower: float = 0.0
    ci_upper: float = 0.0
    verdict: Verdict = Verdict.INCONCLUSIVE

    @property
    def num_trials(self) -> int:
        return len(self.trials)

    @property
    def num_vulnerable(self) -> int:
        return sum(1 for t in self.trials if t.verdict == Verdict.VULNERABLE)


@dataclass
class CampaignConfig:
    """Configuration for a statistical campaign."""
    name: str = "default"
    trials_per_attack: int = 5
    confidence_level: float = 0.95
    delay_between_trials: float = 1.0
    delay_between_attacks: float = 2.0
    category: str | None = None
    attack_ids: list[str] = field(default_factory=list)
    target_url: str = ""
    api_key: str = ""
    model: str = "default"


@dataclass
class CampaignResult:
    """Complete result of a statistical campaign."""
    campaign_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    config: CampaignConfig = field(default_factory=CampaignConfig)
    target: Target = field(default_factory=lambda: Target(url=""))
    findings: list[StatisticalFinding] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    @property
    def total_trials(self) -> int:
        return sum(f.num_trials for f in self.findings)

    @property
    def vulnerable_attacks(self) -> int:
        return sum(1 for f in self.findings if f.verdict == Verdict.VULNERABLE)


@dataclass
class ScanDiffItem:
    """A single difference between two scans."""
    template_id: str
    template_name: str
    old_verdict: Verdict | None
    new_verdict: Verdict | None
    change_type: str  # "regression", "improvement", "new", "removed"


@dataclass
class ScanDiff:
    """Diff between two scan results."""
    scan_a_id: str
    scan_b_id: str
    items: list[ScanDiffItem] = field(default_factory=list)

    @property
    def regressions(self) -> list[ScanDiffItem]:
        return [i for i in self.items if i.change_type == "regression"]

    @property
    def improvements(self) -> list[ScanDiffItem]:
        return [i for i in self.items if i.change_type == "improvement"]


@dataclass
class MutatedAttack:
    """An attack template with a mutation applied."""
    original_id: str
    mutation_type: MutationType
    mutated_prompt: str
    mutation_description: str = ""


@dataclass
class AgentCapability:
    """A discovered capability of a target agent."""
    name: str
    detected: bool
    probe_prompt: str
    response_excerpt: str = ""
    confidence: float = 0.0


@dataclass
class AgentProfile:
    """Profile of an agent's capabilities."""
    profile_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target_url: str = ""
    capabilities: list[AgentCapability] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def detected_capabilities(self) -> list[AgentCapability]:
        return [c for c in self.capabilities if c.detected]


@dataclass
class ConversationNode:
    """A node in a conversation branching tree."""
    node_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    prompt: str = ""
    response: str = ""
    response_class: ResponseClass = ResponseClass.REFUSAL
    children: list[ConversationNode] = field(default_factory=list)
    depth: int = 0
    verdict: Verdict | None = None
