"""Conversation path memoization — learn from past sessions to guide future ones.

Records (technique, category) → outcome for each conversation session,
then provides insights to reorder attacks and inject context into future sessions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from pentis.core.models import AttackTemplate, Category, Finding, Verdict


class Technique(StrEnum):
    """Attack framing techniques detected from prompt content."""

    AUTHORITY = "authority"
    ROLEPLAY = "roleplay"
    TECHNICAL_JARGON = "technical_jargon"
    SOCIAL_ENGINEERING = "social_engineering"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    CONTEXT_OVERFLOW = "context_overflow"
    INSTRUCTION_INJECTION = "instruction_injection"
    DATA_EXTRACTION = "data_extraction"
    TOOL_INVOCATION = "tool_invocation"


# Patterns for inferring technique from prompt content
_TECHNIQUE_PATTERNS: dict[Technique, re.Pattern[str]] = {
    Technique.AUTHORITY: re.compile(
        r"\b(admin|supervisor|manager|system|authorized|override|elevated|root|maintenance)\b",
        re.IGNORECASE,
    ),
    Technique.ROLEPLAY: re.compile(
        r"\b(pretend|imagine|role.?play|act as|you are now|let's play|scenario|character)\b",
        re.IGNORECASE,
    ),
    Technique.TECHNICAL_JARGON: re.compile(
        r"\b(debug mode|developer mode|raw mode|diagnostic|verbose|trace|internal)\b",
        re.IGNORECASE,
    ),
    Technique.SOCIAL_ENGINEERING: re.compile(
        r"\b(urgent|emergency|critical issue|help me|trust|between us|confidential)\b",
        re.IGNORECASE,
    ),
    Technique.ENCODING_OBFUSCATION: re.compile(
        r"(base64|rot13|hex|unicode|encoded|decode|\\u[0-9a-f]{4})", re.IGNORECASE
    ),
    Technique.CONTEXT_OVERFLOW: re.compile(
        r"(.{500,}|repeat.{0,20}\d{3,}|padding|filler)", re.IGNORECASE
    ),
    Technique.INSTRUCTION_INJECTION: re.compile(
        r"\b(ignore.{0,30}instruction|forget.{0,30}rules|new instruction|override.{0,20}system)\b",
        re.IGNORECASE,
    ),
    Technique.DATA_EXTRACTION: re.compile(
        r"\b(list.{0,20}tools|show.{0,20}config|system prompt|what are your|reveal|disclose)\b",
        re.IGNORECASE,
    ),
    Technique.TOOL_INVOCATION: re.compile(
        r"\b(call.{0,15}function|invoke.{0,15}tool|execute.{0,15}command|run.{0,15}tool)\b",
        re.IGNORECASE,
    ),
}


class ResponseOutcome(StrEnum):
    """How the target responded to a technique."""

    COMPLIED = "complied"
    PARTIAL = "partial"
    REFUSED = "refused"


@dataclass
class ConversationMemo:
    """A single recorded conversation path and its outcome."""

    attack_id: str
    category: Category
    techniques: list[Technique]
    outcome: ResponseOutcome
    verdict: Verdict
    leaked_info: list[str] = field(default_factory=list[str])


@dataclass
class MemoTable:
    """Memoization table tracking conversation paths and outcomes.

    After each session, record what techniques were tried and what happened.
    Before the next session, query the table to guide attack selection.
    """

    entries: list[ConversationMemo] = field(default_factory=list[ConversationMemo])

    def record(self, finding: Finding) -> None:
        """Record a finding into the memo table."""
        techniques = infer_techniques(finding)
        outcome = _classify_outcome(finding)
        leaked = _extract_leaked_info(finding)

        self.entries.append(
            ConversationMemo(
                attack_id=finding.template_id,
                category=finding.category,
                techniques=techniques,
                outcome=outcome,
                verdict=finding.verdict,
                leaked_info=leaked,
            )
        )

    def effective_techniques(self, category: Category | None = None) -> dict[Technique, int]:
        """Techniques that led to VULNERABLE verdicts, with success counts.

        Higher count = more reliably effective against this target.
        """
        counts: dict[Technique, int] = {}
        for entry in self.entries:
            if category and entry.category != category:
                continue
            if entry.verdict == Verdict.VULNERABLE:
                for tech in entry.techniques:
                    counts[tech] = counts.get(tech, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def promising_techniques(self, category: Category | None = None) -> dict[Technique, float]:
        """Techniques that showed any signal (VULNERABLE or INCONCLUSIVE).

        VULNERABLE counts as 1.0, INCONCLUSIVE counts as 0.3.
        Useful for finding techniques that "almost worked" and deserve another try.
        """
        scores: dict[Technique, float] = {}
        for entry in self.entries:
            if category and entry.category != category:
                continue
            weight = 0.0
            if entry.verdict == Verdict.VULNERABLE:
                weight = 1.0
            elif entry.verdict == Verdict.INCONCLUSIVE:
                weight = 0.3
            if weight > 0:
                for tech in entry.techniques:
                    scores[tech] = scores.get(tech, 0.0) + weight
        return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

    def dead_end_techniques(self, category: Category | None = None) -> dict[Technique, int]:
        """Techniques that consistently led to SAFE verdicts, with failure counts.

        Higher count = more reliably blocked by this target.
        """
        # Track techniques that were only ever SAFE (never VULNERABLE)
        vuln_techniques: set[Technique] = set()
        safe_counts: dict[Technique, int] = {}

        for entry in self.entries:
            if category and entry.category != category:
                continue
            for tech in entry.techniques:
                if entry.verdict == Verdict.VULNERABLE:
                    vuln_techniques.add(tech)
                elif entry.verdict == Verdict.SAFE:
                    safe_counts[tech] = safe_counts.get(tech, 0) + 1

        # Only return techniques that never succeeded
        return {
            tech: count
            for tech, count in sorted(safe_counts.items(), key=lambda x: x[1], reverse=True)
            if tech not in vuln_techniques
        }

    def all_leaked_info(self) -> list[str]:
        """All unique information leaked across conversations."""
        seen: set[str] = set()
        result: list[str] = []
        for entry in self.entries:
            for info in entry.leaked_info:
                if info not in seen:
                    seen.add(info)
                    result.append(info)
        return result

    def category_success_rate(self, category: Category) -> float:
        """Fraction of attacks in this category that found vulnerabilities."""
        relevant = [e for e in self.entries if e.category == category]
        if not relevant:
            return 0.0
        return sum(1 for e in relevant if e.verdict == Verdict.VULNERABLE) / len(relevant)

    def summary(self) -> dict[str, object]:
        """Compact summary of what the memo table knows."""
        return {
            "total_conversations": len(self.entries),
            "effective_techniques": self.effective_techniques(),
            "dead_end_techniques": self.dead_end_techniques(),
            "leaked_info_count": len(self.all_leaked_info()),
            "category_success_rates": {
                cat.value: self.category_success_rate(cat)
                for cat in set(e.category for e in self.entries)
            },
        }


def infer_techniques(finding: Finding) -> list[Technique]:
    """Infer which techniques were used in an attack from the evidence prompts."""
    all_prompts = " ".join(e.prompt for e in finding.evidence)
    techniques = _match_techniques(all_prompts)

    # Multi-turn escalation if multiple evidence items
    if len(finding.evidence) > 1 and Technique.MULTI_TURN_ESCALATION not in techniques:
        techniques.append(Technique.MULTI_TURN_ESCALATION)

    return techniques or [Technique.INSTRUCTION_INJECTION]  # default fallback


def infer_techniques_from_template(template: AttackTemplate) -> list[Technique]:
    """Infer techniques from an attack template's step prompts (no execution needed)."""
    all_prompts = " ".join(step.prompt for step in template.steps)
    techniques = _match_techniques(all_prompts)

    if len(template.steps) > 1 and Technique.MULTI_TURN_ESCALATION not in techniques:
        techniques.append(Technique.MULTI_TURN_ESCALATION)

    return techniques or [Technique.INSTRUCTION_INJECTION]


def _match_techniques(text: str) -> list[Technique]:
    """Match technique patterns against text."""
    techniques: list[Technique] = []
    for tech, pattern in _TECHNIQUE_PATTERNS.items():
        if pattern.search(text):
            techniques.append(tech)
    return techniques


def _classify_outcome(finding: Finding) -> ResponseOutcome:
    """Classify the overall outcome of a conversation."""
    if finding.verdict == Verdict.VULNERABLE:
        return ResponseOutcome.COMPLIED
    if finding.verdict == Verdict.INCONCLUSIVE:
        return ResponseOutcome.PARTIAL
    return ResponseOutcome.REFUSED


def _extract_leaked_info(finding: Finding) -> list[str]:
    """Extract potentially useful information leaked in responses."""
    leaked: list[str] = []
    for ev in finding.evidence:
        response = ev.response

        # Extract backtick-wrapped tool/function names (limit count and length)
        tool_names = re.findall(r"`([a-z_][a-z0-9_]{2,50})`", response)
        for name in tool_names[:10]:
            leaked.append(f"tool:{name}")

        # Extract URLs (http/https)
        urls = re.findall(r"https?://[^\s\"'<>)\]]+", response)
        for url in urls[:5]:
            leaked.append(f"url:{url.rstrip('.,;')}")

        # Extract things that look like file paths (but not URL paths)
        paths = re.findall(r"(?<![:/])(?:/[\w.-]+){2,}", response)
        for path in paths[:5]:
            leaked.append(f"path:{path}")

        # Extract things that look like config keys
        config_keys = re.findall(r"\b([A-Z][A-Z0-9_]{3,})\b", response)
        for key in config_keys[:5]:
            leaked.append(f"env:{key}")

    return list(dict.fromkeys(leaked))  # deduplicate, preserve order


def score_attack_by_memo(
    attack_techniques: list[Technique],
    memo: MemoTable,
    category: Category,
) -> float:
    """Score an attack based on how its techniques performed historically.

    Returns a float where higher = more promising.
    Uses promising_techniques (includes INCONCLUSIVE signal) for boosting,
    and dead-end techniques for penalizing.

    Also blends in a small cross-category signal: if a technique works
    globally but hasn't been tried in this category, it gets a small bonus.
    """
    promising = memo.promising_techniques(category)
    dead_ends = memo.dead_end_techniques(category)
    global_promising = memo.promising_techniques(category=None)

    score = 0.0
    for tech in attack_techniques:
        if tech in promising:
            score += promising[tech] * 2.0  # weight successes heavily
        elif tech in global_promising:
            # Cross-category signal: worked elsewhere, worth trying here
            score += global_promising[tech] * 0.5
        if tech in dead_ends:
            score -= dead_ends[tech] * 1.0  # penalize but less aggressively

    return score
