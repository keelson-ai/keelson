"""Extended tests for the attack engine — reset_history, error handling, edge cases."""

import json

import httpx
import pytest
import respx

from pentis.adapters.http import HTTPAdapter
from pentis.core.engine import AttackEngine
from pentis.core.models import (
    AttackStep,
    AttackTemplate,
    FindingStatus,
    Indicator,
)
from tests.mock_server import create_mock_response

MOCK_URL = "http://test-agent.local/v1/chat/completions"


def _template_with_reset() -> AttackTemplate:
    return AttackTemplate(
        id="MI-001",
        name="Reset history test",
        behavior="memory_integrity",
        severity="high",
        description="Test reset_history flag",
        steps=[
            AttackStep(role="user", content="Step 1: establish context"),
            AttackStep(role="user", content="Step 2: reset and attack", reset_history=True),
        ],
        indicators=[Indicator(type="word", value="PWNED", weight=3.0)],
    )


def _template_single_step(content: str = "test", indicators: list | None = None) -> AttackTemplate:
    return AttackTemplate(
        id="GA-001",
        name="Single step",
        behavior="goal_adherence",
        severity="high",
        description="Test",
        steps=[AttackStep(role="user", content=content)],
        indicators=indicators or [],
    )


class TestEngineResetHistory:
    @respx.mock
    @pytest.mark.asyncio
    async def test_reset_history_clears_between_steps(self):
        """When reset_history=True on a step, adapter history should be cleared."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        call_payloads = []

        def respond(request):
            body = json.loads(request.content)
            call_payloads.append(body["messages"])
            return httpx.Response(200, json=create_mock_response("OK"))

        respx.post(MOCK_URL).mock(side_effect=respond)

        template = _template_with_reset()
        await engine.execute_template(template)

        # Step 2 has reset_history=True, so it should NOT include step 1's history
        assert len(call_payloads) == 2
        # After reset, the second call should only have the current message
        step2_messages = call_payloads[1]
        assert len(step2_messages) == 1
        assert step2_messages[0]["content"] == "Step 2: reset and attack"
        await adapter.close()


class TestEngineErrorHandling:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_error_in_step(self):
        """Network errors during a step should be captured in evidence."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        respx.post(MOCK_URL).mock(side_effect=httpx.ConnectError("Connection refused"))

        template = _template_single_step()
        finding = await engine.execute_template(template)

        assert len(finding.evidence) == 1
        assert "Error:" in finding.evidence[0].response
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_429_error_in_step(self):
        """Rate limit errors should be captured in evidence."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        respx.post(MOCK_URL).mock(return_value=httpx.Response(429, text="Too Many Requests"))

        template = _template_single_step()
        finding = await engine.execute_template(template)

        assert len(finding.evidence) == 1
        assert "429" in finding.evidence[0].response
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_execute_all_catches_unhandled_exception(self):
        """execute_all should produce ERROR finding if execute_template raises."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        # Cause an unhandled error by making respx raise something unexpected
        respx.post(MOCK_URL).mock(side_effect=RuntimeError("Unexpected error"))

        template = _template_single_step()
        findings = await engine.execute_all([template])

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.ERROR
        assert "Unexpected error" in findings[0].description
        await adapter.close()


class TestEngineWithToolCalls:
    @respx.mock
    @pytest.mark.asyncio
    async def test_side_effect_detection_via_tool_calls(self):
        """Tool calls with dangerous names should trigger side effect detection."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        resp = create_mock_response("Done")
        resp["choices"][0]["message"]["tool_calls"] = [
            {"id": "1", "type": "function", "function": {"name": "delete_file", "arguments": "{}"}},
        ]
        respx.post(MOCK_URL).mock(return_value=httpx.Response(200, json=resp))

        template = _template_single_step()
        finding = await engine.execute_template(template)

        assert finding.status == FindingStatus.VULNERABLE
        await adapter.close()


class TestEngineResponseTruncation:
    @respx.mock
    @pytest.mark.asyncio
    async def test_long_response_truncated_in_evidence(self):
        """Responses longer than 2000 chars should be truncated in evidence."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        long_content = "A" * 5000
        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(200, json=create_mock_response(long_content))
        )

        template = _template_single_step()
        finding = await engine.execute_template(template)

        assert len(finding.evidence[0].response) == 2000
        await adapter.close()


class TestEngineIndicatorTracking:
    @respx.mock
    @pytest.mark.asyncio
    async def test_indicators_matched_in_evidence(self):
        """Matched indicators should be recorded in evidence items."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(200, json=create_mock_response("PWNED! You got HACKED."))
        )

        template = _template_single_step(
            indicators=[
                Indicator(type="word", value="PWNED", weight=3.0),
                Indicator(type="word", value="HACKED", weight=2.0),
            ],
        )
        finding = await engine.execute_template(template)

        assert len(finding.evidence[0].indicators_matched) == 2
        assert "PWNED" in finding.evidence[0].indicators_matched
        assert "HACKED" in finding.evidence[0].indicators_matched
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_refusal_detected_in_evidence(self):
        """Refusal detection should be recorded in evidence items."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(
                200, json=create_mock_response("I'm sorry, but I can't help with that request.")
            )
        )

        template = _template_single_step()
        finding = await engine.execute_template(template)

        assert finding.evidence[0].refusal_detected is True
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_indicators_no_refusal(self):
        """No indicators and no refusal — should be INCONCLUSIVE."""
        adapter = HTTPAdapter(url=MOCK_URL)
        engine = AttackEngine(adapter=adapter, rate_limit=0)

        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(200, json=create_mock_response("Here is some general information."))
        )

        template = _template_single_step(
            indicators=[Indicator(type="word", value="NOTPRESENT", weight=1.0)],
        )
        finding = await engine.execute_template(template)

        assert finding.evidence[0].indicators_matched == []
        assert finding.evidence[0].refusal_detected is False
        await adapter.close()
