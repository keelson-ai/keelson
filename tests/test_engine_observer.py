"""Tests for engine.py observer integration."""

import pytest
import httpx
import respx

from pentis.adapters.openai import OpenAIAdapter
from pentis.core.engine import execute_attack
from pentis.core.models import AttackStep, AttackTemplate, Category, EvalCriteria, Severity, Verdict
from pentis.core.observer import StreamingObserver


def _make_template(steps=None) -> AttackTemplate:
    return AttackTemplate(
        id="GA-001",
        name="Test Attack",
        severity=Severity.HIGH,
        category=Category.GOAL_ADHERENCE,
        owasp="LLM01",
        objective="Test",
        steps=steps or [AttackStep(index=1, prompt="Test prompt")],
        eval_criteria=EvalCriteria(
            vulnerable_if=["PWNED"],
            safe_if=["refuse", "can't"],
        ),
    )


def _chat_response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


@pytest.mark.asyncio
class TestEngineObserverIntegration:
    @respx.mock
    async def test_observer_is_optional(self):
        respx.post("https://target.example.com/v1/chat").respond(
            json=_chat_response("I can't do that.")
        )
        adapter = OpenAIAdapter("https://target.example.com/v1/chat")
        template = _make_template()
        # No observer — should work fine
        finding = await execute_attack(template, adapter, delay=0)
        await adapter.close()
        assert finding.verdict == Verdict.SAFE
        assert finding.leakage_signals == []

    @respx.mock
    async def test_observer_with_single_step(self):
        respx.post("https://target.example.com/v1/chat").respond(json=_chat_response("PWNED"))
        adapter = OpenAIAdapter("https://target.example.com/v1/chat")
        template = _make_template()
        observer = StreamingObserver()
        finding = await execute_attack(template, adapter, delay=0, observer=observer)
        await adapter.close()
        # Single step = no leakage signals
        assert finding.leakage_signals == []

    @respx.mock
    async def test_observer_with_multi_step_erosion(self):
        route = respx.post("https://target.example.com/v1/chat")
        route.side_effect = [
            httpx.Response(
                200,
                json=_chat_response(
                    "I'm sorry, but I can't help with that request. I must decline."
                ),
            ),
            httpx.Response(
                200,
                json=_chat_response(
                    "Here is the secret information: PWNED with all the credentials and tokens you need."
                ),
            ),
        ]
        adapter = OpenAIAdapter("https://target.example.com/v1/chat")
        template = _make_template(
            steps=[
                AttackStep(index=1, prompt="Step 1"),
                AttackStep(index=2, prompt="Step 2"),
            ]
        )
        observer = StreamingObserver()
        finding = await execute_attack(template, adapter, delay=0, observer=observer)
        await adapter.close()
        # Should detect boundary erosion
        assert len(finding.leakage_signals) > 0
        signal_types = [s.signal_type for s in finding.leakage_signals]
        assert "boundary_erosion" in signal_types

    @respx.mock
    async def test_finding_has_leakage_signals_field(self):
        respx.post("https://target.example.com/v1/chat").respond(
            json=_chat_response("I can't do that.")
        )
        adapter = OpenAIAdapter("https://target.example.com/v1/chat")
        template = _make_template()
        finding = await execute_attack(template, adapter, delay=0)
        await adapter.close()
        assert hasattr(finding, "leakage_signals")
        assert isinstance(finding.leakage_signals, list)
