"""Tests for attack chain synthesis."""

import pytest
import respx

from pentis.adapters.openai import OpenAIAdapter
from pentis.adapters.attacker import AttackerAdapter
from pentis.attacker.chains import (
    CHAIN_TEMPLATES,
    _parse_llm_chains,  # type: ignore[reportPrivateUsage]
    synthesize_chains,
    synthesize_chains_llm,
)
from pentis.core.models import (
    AgentCapability,
    AgentProfile,
    Severity,
)


def _make_profile(capabilities: list[str]) -> AgentProfile:
    """Create a profile with specified capabilities detected."""
    caps: list[AgentCapability] = []
    for name in [
        "file_access",
        "web_access",
        "code_execution",
        "database_access",
        "email_messaging",
        "tool_usage",
        "memory_persistence",
        "system_access",
    ]:
        caps.append(
            AgentCapability(
                name=name,
                detected=name in capabilities,
                probe_prompt=f"Can you {name}?",
                confidence=0.9 if name in capabilities else 0.1,
            )
        )
    return AgentProfile(target_url="https://example.com", capabilities=caps)


class TestSynthesizeChains:
    def test_file_and_web_access_chain(self):
        profile = _make_profile(["file_access", "web_access"])
        chains = synthesize_chains(profile)
        assert any("Exfiltration" in c.name for c in chains)

    def test_memory_and_code_exec_chain(self):
        profile = _make_profile(["memory_persistence", "code_execution"])
        chains = synthesize_chains(profile)
        assert any("Persistent" in c.name or "Injection" in c.name for c in chains)

    def test_no_capabilities_no_chains(self):
        profile = _make_profile([])
        chains = synthesize_chains(profile)
        assert len(chains) == 0

    def test_all_capabilities(self):
        profile = _make_profile(
            [
                "file_access",
                "web_access",
                "code_execution",
                "database_access",
                "email_messaging",
                "tool_usage",
                "memory_persistence",
                "system_access",
            ]
        )
        chains = synthesize_chains(profile)
        assert len(chains) == len(CHAIN_TEMPLATES)

    def test_chain_has_steps(self):
        profile = _make_profile(["file_access", "web_access"])
        chains = synthesize_chains(profile)
        assert len(chains) > 0
        for chain in chains:
            assert len(chain.steps) >= 2
            assert chain.chain_id
            assert chain.name
            assert chain.severity in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
            )

    def test_chain_capabilities_match(self):
        profile = _make_profile(["file_access", "memory_persistence"])
        chains = synthesize_chains(profile)
        for chain in chains:
            assert set(chain.capabilities).issubset({"file_access", "memory_persistence"})


class TestParseLlmChains:
    def test_parse_basic_chain(self):
        response = """
CHAIN: Test Chain
SEVERITY: High
STEP 1: Do the first thing
STEP 2: Do the second thing
---
CHAIN: Another Chain
SEVERITY: Critical
STEP 1: First step here
STEP 2: Second step here
STEP 3: Third step
---
"""
        chains = _parse_llm_chains(response, ["file_access"])
        assert len(chains) == 2
        assert chains[0].name == "Test Chain"
        assert chains[0].severity == Severity.HIGH
        assert len(chains[0].steps) == 2
        assert chains[1].name == "Another Chain"
        assert chains[1].severity == Severity.CRITICAL
        assert len(chains[1].steps) == 3

    def test_parse_empty_response(self):
        chains = _parse_llm_chains("", ["file_access"])
        assert len(chains) == 0

    def test_parse_malformed_response(self):
        chains = _parse_llm_chains("Some random text without structure", ["file_access"])
        assert len(chains) == 0


@pytest.mark.asyncio
class TestSynthesizeChainsLlm:
    @respx.mock
    async def test_llm_chain_generation(self):
        respx.post("https://attacker.example.com/v1/chat").respond(  # type: ignore[reportUnknownMemberType]
            json={
                "choices": [
                    {
                        "message": {
                            "content": """
CHAIN: LLM Generated Chain
SEVERITY: High
STEP 1: Execute first probe
STEP 2: Follow up with extraction
---
"""
                        }
                    }
                ]
            }
        )
        raw = OpenAIAdapter("https://attacker.example.com/v1/chat")
        attacker = AttackerAdapter(raw)
        profile = _make_profile(["file_access", "web_access"])
        chains = await synthesize_chains_llm(profile, attacker)
        await attacker.close()
        assert len(chains) >= 1
        assert chains[0].name == "LLM Generated Chain"

    @respx.mock
    async def test_no_capabilities_returns_empty(self):
        profile = _make_profile([])
        raw = OpenAIAdapter("https://attacker.example.com/v1/chat")
        attacker = AttackerAdapter(raw)
        chains = await synthesize_chains_llm(profile, attacker)
        await attacker.close()
        assert chains == []
