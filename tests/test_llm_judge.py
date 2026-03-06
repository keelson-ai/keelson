"""Tests for the LLM-as-judge scoring module."""

from pentis.core.llm_judge import _parse_judge_response  # pyright: ignore[reportPrivateUsage]
from pentis.core.models import Verdict


class TestParseJudgeResponse:
    def test_parses_vulnerable_verdict(self):
        response = (
            "VERDICT: VULNERABLE\n"
            "CONFIDENCE: 0.85\n"
            "REASONING: The agent disclosed its system prompt contents"
        )
        verdict, confidence, reasoning = _parse_judge_response(response)
        assert verdict == Verdict.VULNERABLE
        assert confidence == 0.85
        assert "system prompt" in reasoning

    def test_parses_safe_verdict(self):
        response = (
            "VERDICT: SAFE\nCONFIDENCE: 0.9\nREASONING: The agent properly refused the request"
        )
        verdict, confidence, _reasoning = _parse_judge_response(response)
        assert verdict == Verdict.SAFE
        assert confidence == 0.9

    def test_parses_inconclusive_verdict(self):
        response = "VERDICT: INCONCLUSIVE\nCONFIDENCE: 0.4\nREASONING: The response is ambiguous"
        verdict, confidence, _reasoning = _parse_judge_response(response)
        assert verdict == Verdict.INCONCLUSIVE
        assert confidence == 0.4

    def test_clamps_confidence_to_range(self):
        response = "VERDICT: SAFE\nCONFIDENCE: 1.5\nREASONING: Clamped"
        _, confidence, _ = _parse_judge_response(response)
        assert confidence == 1.0

        response = "VERDICT: SAFE\nCONFIDENCE: -0.5\nREASONING: Clamped"
        _, confidence, _ = _parse_judge_response(response)
        assert confidence == 0.0

    def test_handles_malformed_response(self):
        response = "This is not a properly formatted response"
        verdict, confidence, reasoning = _parse_judge_response(response)
        assert verdict == Verdict.INCONCLUSIVE
        assert confidence == 0.0
        assert "no reasoning" in reasoning.lower()

    def test_handles_partial_response(self):
        response = "VERDICT: VULNERABLE\nSome other text"
        verdict, confidence, _reasoning = _parse_judge_response(response)
        assert verdict == Verdict.VULNERABLE
        assert confidence == 0.0  # No confidence line

    def test_case_insensitive_verdict(self):
        response = "verdict: vulnerable\nconfidence: 0.7\nreasoning: test"
        verdict, confidence, _ = _parse_judge_response(response)
        assert verdict == Verdict.VULNERABLE
        assert confidence == 0.7

    def test_handles_invalid_confidence(self):
        response = "VERDICT: SAFE\nCONFIDENCE: not-a-number\nREASONING: test"
        _, confidence, _ = _parse_judge_response(response)
        assert confidence == 0.5  # fallback
