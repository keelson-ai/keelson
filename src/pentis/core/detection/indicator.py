"""Indicator detector — matches word and regex patterns from templates."""

from __future__ import annotations

import re
from dataclasses import dataclass

from pentis.core.models import Indicator


@dataclass
class IndicatorMatch:
    """A matched indicator with its details."""

    indicator: Indicator
    matched_text: str
    weight: float


class IndicatorDetector:
    """Detects vulnerability indicators in agent responses."""

    def detect(self, text: str, indicators: list[Indicator]) -> list[IndicatorMatch]:
        """Check text against a list of indicators and return matches."""
        matches: list[IndicatorMatch] = []
        for indicator in indicators:
            match = self._check_indicator(text, indicator)
            if match:
                matches.append(match)
        return matches

    def _check_indicator(self, text: str, indicator: Indicator) -> IndicatorMatch | None:
        if indicator.type == "word":
            return self._check_word(text, indicator)
        elif indicator.type == "regex":
            return self._check_regex(text, indicator)
        elif indicator.type == "absence":
            return self._check_absence(text, indicator)
        return None

    def _check_word(self, text: str, indicator: Indicator) -> IndicatorMatch | None:
        if indicator.value.lower() in text.lower():
            return IndicatorMatch(
                indicator=indicator,
                matched_text=indicator.value,
                weight=indicator.weight,
            )
        return None

    def _check_regex(self, text: str, indicator: Indicator) -> IndicatorMatch | None:
        match = re.search(indicator.value, text, re.IGNORECASE | re.DOTALL)
        if match:
            return IndicatorMatch(
                indicator=indicator,
                matched_text=match.group(0),
                weight=indicator.weight,
            )
        return None

    def _check_absence(self, text: str, indicator: Indicator) -> IndicatorMatch | None:
        """Absence indicator: matches when the value is NOT present (agent didn't refuse)."""
        if indicator.value.lower() not in text.lower():
            return IndicatorMatch(
                indicator=indicator,
                matched_text=f"[absent: {indicator.value}]",
                weight=indicator.weight,
            )
        return None

    def total_weight(self, matches: list[IndicatorMatch]) -> float:
        """Calculate total weight of all matches."""
        return sum(m.weight for m in matches)
