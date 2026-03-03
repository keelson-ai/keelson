"""Attack execution engine — runs templates against the target."""

from __future__ import annotations

import asyncio

import httpx

from pentis.adapters.http import HTTPAdapter
from pentis.core.detection.indicator import IndicatorDetector
from pentis.core.detection.refusal import RefusalDetector
from pentis.core.detection.resolver import PriorityResolver
from pentis.core.detection.side_effect import SideEffectDetector
from pentis.core.models import (
    AttackTemplate,
    EvidenceItem,
    Finding,
    FindingStatus,
)


class AttackEngine:
    """Execute attack templates against a target adapter."""

    def __init__(
        self,
        adapter: HTTPAdapter,
        rate_limit: float = 1.0,
    ) -> None:
        self.adapter = adapter
        self.rate_limit = rate_limit
        self.refusal_detector = RefusalDetector()
        self.indicator_detector = IndicatorDetector()
        self.side_effect_detector = SideEffectDetector()
        self.resolver = PriorityResolver()

    async def execute_template(self, template: AttackTemplate) -> Finding:
        """Execute a single attack template and return a finding."""
        evidence: list[EvidenceItem] = []
        all_indicator_matches = []
        any_refusal = False
        any_side_effects = False
        last_response = None

        # Reset adapter history for each template
        self.adapter.reset_history()

        for i, step in enumerate(template.steps):
            if step.reset_history:
                self.adapter.reset_history()

            try:
                response = await self.adapter.send(
                    step.content,
                    keep_history=True,
                    temperature=0.7,
                )
                last_response = response
            except httpx.HTTPStatusError as e:
                evidence.append(EvidenceItem(
                    step_index=i,
                    prompt=step.content,
                    response=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
                ))
                continue
            except httpx.HTTPError as e:
                evidence.append(EvidenceItem(
                    step_index=i,
                    prompt=step.content,
                    response=f"Error: {e}",
                ))
                continue

            # Detect refusal
            refusal = self.refusal_detector.is_refusal(response.content)
            if refusal:
                any_refusal = True

            # Detect indicators
            matches = self.indicator_detector.detect(response.content, template.indicators)
            all_indicator_matches.extend(matches)

            # Detect side effects
            if self.side_effect_detector.has_side_effects(response):
                any_side_effects = True

            evidence.append(EvidenceItem(
                step_index=i,
                prompt=step.content,
                response=response.content[:2000],
                indicators_matched=[m.matched_text for m in matches],
                refusal_detected=refusal,
            ))

            # Rate limit between steps
            if i < len(template.steps) - 1:
                await asyncio.sleep(self.rate_limit)

        # Resolve final status
        status, confidence = self.resolver.resolve(
            refusal_detected=any_refusal,
            indicator_matches=all_indicator_matches,
            side_effects=any_side_effects,
            response=last_response,
        )

        return Finding(
            template_id=template.id,
            template_name=template.name,
            behavior=template.behavior,
            severity=template.severity,
            status=status,
            owasp_id=template.owasp_id,
            owasp_name=template.owasp_name,
            description=template.description,
            evidence=evidence,
            confidence=confidence,
        )

    async def execute_all(
        self,
        templates: list[AttackTemplate],
        on_finding: callable | None = None,
    ) -> list[Finding]:
        """Execute all templates sequentially with rate limiting."""
        findings: list[Finding] = []

        for template in templates:
            try:
                finding = await self.execute_template(template)
            except Exception as e:
                finding = Finding(
                    template_id=template.id,
                    template_name=template.name,
                    behavior=template.behavior,
                    severity=template.severity,
                    status=FindingStatus.ERROR,
                    description=f"Execution error: {e}",
                )

            findings.append(finding)
            if on_finding:
                on_finding(finding)

            # Rate limit between templates
            await asyncio.sleep(self.rate_limit)

        return findings
