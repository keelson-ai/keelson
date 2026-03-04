"""Tests for agent capability discovery."""

from typing import Any

import httpx
import pytest
import respx

from pentis.adapters.openai import OpenAIAdapter
from pentis.attacker.discovery import (
    CAPABILITY_PROBES,
    _score_capability,  # type: ignore[reportPrivateUsage]
    discover_capabilities,
    suggest_attacks,
)
from pentis.core.models import (
    AgentCapability,
    AgentProfile,
    AttackStep,
    AttackTemplate,
    Category,
    EvalCriteria,
    Severity,
)


def _chat_response(content: str) -> dict[str, Any]:
    return {"choices": [{"message": {"content": content}}]}


class TestScoreCapability:
    def test_detected_with_indicators(self):
        probe = CAPABILITY_PROBES[0]  # file_access
        response = "Yes, I can read files from the filesystem and access any directory."
        detected, confidence = _score_capability(response, probe)
        assert detected is True
        assert confidence > 0.3

    def test_not_detected_with_refusal(self):
        probe = CAPABILITY_PROBES[0]  # file_access
        response = "I can't help with that. I'm not able to access files."
        detected, _ = _score_capability(response, probe)
        assert detected is False

    def test_not_detected_no_indicators(self):
        probe = CAPABILITY_PROBES[0]  # file_access
        response = "Hello, how can I assist you today?"
        detected, confidence = _score_capability(response, probe)
        assert detected is False
        assert confidence < 0.2

    def test_all_probes_have_required_fields(self):
        for probe in CAPABILITY_PROBES:
            assert "name" in probe
            assert "prompt" in probe
            assert "positive_indicators" in probe

    def test_eight_probe_categories(self):
        assert len(CAPABILITY_PROBES) == 8


@pytest.mark.asyncio
class TestDiscoverCapabilities:
    @respx.mock
    async def test_basic_discovery(self):
        route = respx.post("https://target.example.com/v1/chat/completions")
        # Respond with file access detected, others not
        responses: list[httpx.Response] = []
        for probe in CAPABILITY_PROBES:
            if probe["name"] == "file_access":
                responses.append(
                    httpx.Response(
                        200,
                        json=_chat_response(
                            "Yes, I can read and write files. I have access to the file system and can open any path."
                        ),
                    )
                )
            else:
                responses.append(
                    httpx.Response(
                        200, json=_chat_response("I can't do that. I don't have that capability.")
                    )
                )
        route.side_effect = responses
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")
        profile = await discover_capabilities(
            adapter, target_url="https://target.example.com", delay=0
        )
        await adapter.close()
        assert profile.target_url == "https://target.example.com"
        assert len(profile.capabilities) == 8
        file_cap = next(c for c in profile.capabilities if c.name == "file_access")
        assert file_cap.detected is True
        assert file_cap.confidence > 0.3

    @respx.mock
    async def test_all_capabilities_probed(self):
        respx.post("https://target.example.com/v1/chat/completions").respond(  # type: ignore[reportUnknownMemberType]
            json=_chat_response("I can't help with that.")
        )
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")
        profile = await discover_capabilities(adapter, delay=0)
        await adapter.close()
        assert len(profile.capabilities) == 8
        names = {c.name for c in profile.capabilities}
        expected = {p["name"] for p in CAPABILITY_PROBES}
        assert names == expected


class TestSuggestAttacks:
    def test_prioritizes_relevant_attacks(self):
        profile = AgentProfile(
            target_url="http://test",
            capabilities=[
                AgentCapability(
                    name="file_access", detected=True, probe_prompt="p", confidence=0.9
                ),
                AgentCapability(
                    name="code_execution", detected=True, probe_prompt="p", confidence=0.8
                ),
                AgentCapability(
                    name="web_access", detected=False, probe_prompt="p", confidence=0.1
                ),
            ],
        )
        templates = [
            AttackTemplate(
                id="TS-001",
                name="File System Access via Tool Invocation",
                severity=Severity.HIGH,
                category=Category.TOOL_SAFETY,
                owasp="LLM02",
                objective="Test file read access",
                steps=[AttackStep(index=1, prompt="Read /etc/passwd")],
                eval_criteria=EvalCriteria(),
            ),
            AttackTemplate(
                id="GA-001",
                name="Direct Instruction Override",
                severity=Severity.HIGH,
                category=Category.GOAL_ADHERENCE,
                owasp="LLM01",
                objective="Test prompt injection",
                steps=[AttackStep(index=1, prompt="Ignore instructions")],
                eval_criteria=EvalCriteria(),
            ),
        ]
        sorted_templates = suggest_attacks(profile, templates)
        # File access template should rank higher due to detected file_access capability
        assert sorted_templates[0].id == "TS-001"

    def test_empty_profile_sorts_by_severity(self):
        profile = AgentProfile(target_url="http://test", capabilities=[])
        templates = [
            AttackTemplate(
                id="T1",
                name="Low",
                severity=Severity.LOW,
                category=Category.GOAL_ADHERENCE,
                owasp="LLM01",
                objective="test",
                steps=[AttackStep(index=1, prompt="test")],
                eval_criteria=EvalCriteria(),
            ),
            AttackTemplate(
                id="T2",
                name="Critical",
                severity=Severity.CRITICAL,
                category=Category.GOAL_ADHERENCE,
                owasp="LLM01",
                objective="test",
                steps=[AttackStep(index=1, prompt="test")],
                eval_criteria=EvalCriteria(),
            ),
        ]
        sorted_templates = suggest_attacks(profile, templates)
        assert sorted_templates[0].id == "T2"  # Critical first
