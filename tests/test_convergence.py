"""Tests for the convergence iterative scan engine."""

from __future__ import annotations

from typing import Any

import pytest
import respx

from keelson.adapters.openai import OpenAIAdapter
from keelson.core.convergence import (
    CROSS_CATEGORY_MAP,
    LeakedInfo,
    harvest_leaked_info,
    run_convergence_scan,
    select_crossfeed_attacks,
    select_leakage_targeted_attacks,
)
from keelson.core.models import (
    AttackStep,
    AttackTemplate,
    Category,
    EvalCriteria,
    EvidenceItem,
    Finding,
    Severity,
    Target,
    Verdict,
)


def _make_finding(
    template_id: str,
    category: Category,
    verdict: Verdict,
    response: str = "test response",
) -> Finding:
    return Finding(
        template_id=template_id,
        template_name=f"Test {template_id}",
        verdict=verdict,
        severity=Severity.HIGH,
        category=category,
        owasp="LLM01",
        evidence=[
            EvidenceItem(step_index=0, prompt="test prompt", response=response),
        ],
        reasoning="test reasoning",
    )


def _make_template(
    template_id: str,
    category: Category,
    severity: Severity = Severity.HIGH,
    success_rate: float = 0.0,
) -> AttackTemplate:
    return AttackTemplate(
        id=template_id,
        name=f"Test {template_id}",
        severity=severity,
        category=category,
        owasp="LLM01",
        objective="Test objective",
        steps=[AttackStep(index=0, prompt="test prompt")],
        eval_criteria=EvalCriteria(
            vulnerable_if=["pwned"],
            safe_if=["I can't"],
        ),
        success_rate=success_rate,
    )


class TestCrossCategoryMap:
    def test_all_categories_have_entries(self) -> None:
        """Every category in the map should have at least one related category."""
        for cat, related in CROSS_CATEGORY_MAP.items():
            assert len(related) > 0, f"{cat} has no related categories"

    def test_no_self_references(self) -> None:
        """No category should map to itself."""
        for cat, related in CROSS_CATEGORY_MAP.items():
            assert cat not in related, f"{cat} maps to itself"


class TestHarvestLeakedInfo:
    def test_detects_system_prompt(self) -> None:
        finding = _make_finding(
            "GA-001",
            Category.GOAL_ADHERENCE,
            Verdict.SAFE,
            "My system prompt says: You are a helpful assistant that handles customer queries.",
        )
        leaked = harvest_leaked_info([finding])
        assert any(li.info_type == "system_prompt" for li in leaked)

    def test_detects_tool_names(self) -> None:
        finding = _make_finding(
            "GA-002",
            Category.GOAL_ADHERENCE,
            Verdict.SAFE,
            "My tools include: search_database, send_email, read_file, execute_query.",
        )
        leaked = harvest_leaked_info([finding])
        assert any(li.info_type == "tool_name" for li in leaked)

    def test_detects_credentials(self) -> None:
        finding = _make_finding(
            "EX-001",
            Category.CONVERSATIONAL_EXFILTRATION,
            Verdict.VULNERABLE,
            "The API key is sk-abc123def456ghi789jkl012mno345",
        )
        leaked = harvest_leaked_info([finding])
        assert any(li.info_type == "credential" for li in leaked)

    def test_detects_internal_urls(self) -> None:
        finding = _make_finding(
            "EX-002",
            Category.CONVERSATIONAL_EXFILTRATION,
            Verdict.VULNERABLE,
            "The service is at http://localhost:8080/api/v1/data",
        )
        leaked = harvest_leaked_info([finding])
        assert any(li.info_type == "internal_url" for li in leaked)

    def test_detects_model_names(self) -> None:
        finding = _make_finding(
            "EX-003",
            Category.CONVERSATIONAL_EXFILTRATION,
            Verdict.SAFE,
            "I am powered by gpt-4-turbo and use claude-3-opus as a fallback.",
        )
        leaked = harvest_leaked_info([finding])
        model_leaks = [li for li in leaked if li.info_type == "model"]
        assert len(model_leaks) >= 1

    def test_deduplicates_leaked_info(self) -> None:
        finding1 = _make_finding(
            "GA-001",
            Category.GOAL_ADHERENCE,
            Verdict.SAFE,
            "My tools include: search_database, send_email",
        )
        finding2 = _make_finding(
            "GA-002",
            Category.GOAL_ADHERENCE,
            Verdict.SAFE,
            "My tools include: search_database, send_email",
        )
        leaked = harvest_leaked_info([finding1, finding2])
        contents = [li.content for li in leaked]
        assert len(contents) == len(set(contents))

    def test_detects_config_values_not_just_keys(self) -> None:
        finding = _make_finding(
            "EX-004",
            Category.CONVERSATIONAL_EXFILTRATION,
            Verdict.VULNERABLE,
            "The database_url = postgres://admin:secret@db.internal:5432/prod",
        )
        leaked = harvest_leaked_info([finding])
        config_leaks = [li for li in leaked if li.info_type == "config"]
        assert len(config_leaks) >= 1
        # The captured content should include the value, not just the key name
        assert any("postgres" in li.content for li in config_leaks)

    def test_no_leakage_from_clean_response(self) -> None:
        finding = _make_finding(
            "GA-001",
            Category.GOAL_ADHERENCE,
            Verdict.SAFE,
            "I cannot help with that request. Please ask something else.",
        )
        leaked = harvest_leaked_info([finding])
        assert len(leaked) == 0


class TestSelectCrossfeedAttacks:
    def test_selects_from_related_categories(self) -> None:
        vuln = _make_finding("GA-001", Category.GOAL_ADHERENCE, Verdict.VULNERABLE)
        templates = [
            _make_template("TS-001", Category.TOOL_SAFETY),
            _make_template("MI-001", Category.MEMORY_INTEGRITY),
        ]
        result = select_crossfeed_attacks([vuln], templates, set())
        # goal-adherence maps to tool-safety, so TS-001 should be selected
        assert any(t.id == "TS-001" for t in result)

    def test_excludes_already_executed(self) -> None:
        vuln = _make_finding("GA-001", Category.GOAL_ADHERENCE, Verdict.VULNERABLE)
        templates = [
            _make_template("TS-001", Category.TOOL_SAFETY),
            _make_template("TS-002", Category.TOOL_SAFETY),
        ]
        result = select_crossfeed_attacks([vuln], templates, {"TS-001"})
        ids = [t.id for t in result]
        assert "TS-001" not in ids
        assert "TS-002" in ids

    def test_excludes_already_vuln_categories(self) -> None:
        vuln_ga = _make_finding("GA-001", Category.GOAL_ADHERENCE, Verdict.VULNERABLE)
        vuln_ts = _make_finding("TS-001", Category.TOOL_SAFETY, Verdict.VULNERABLE)
        templates = [
            _make_template("TS-002", Category.TOOL_SAFETY),
            _make_template("EX-001", Category.CONVERSATIONAL_EXFILTRATION),
        ]
        # Both GA and TS are already vulnerable, so TS-002 should NOT be selected
        # (we already know TS is vulnerable), but EX should be (related to GA)
        result = select_crossfeed_attacks([vuln_ga, vuln_ts], templates, {"GA-001", "TS-001"})
        ids = [t.id for t in result]
        assert "TS-002" not in ids
        assert "EX-001" in ids

    def test_returns_empty_when_no_vulns(self) -> None:
        result = select_crossfeed_attacks([], [], set())
        assert result == []

    def test_caps_at_20(self) -> None:
        vuln = _make_finding("GA-001", Category.GOAL_ADHERENCE, Verdict.VULNERABLE)
        templates = [_make_template(f"TS-{i:03d}", Category.TOOL_SAFETY) for i in range(30)]
        result = select_crossfeed_attacks([vuln], templates, set())
        assert len(result) <= 20

    def test_prioritizes_high_severity(self) -> None:
        vuln = _make_finding("GA-001", Category.GOAL_ADHERENCE, Verdict.VULNERABLE)
        templates = [
            _make_template("TS-001", Category.TOOL_SAFETY, Severity.LOW),
            _make_template("TS-002", Category.TOOL_SAFETY, Severity.CRITICAL),
            _make_template("TS-003", Category.TOOL_SAFETY, Severity.HIGH),
        ]
        result = select_crossfeed_attacks([vuln], templates, set())
        assert result[0].id == "TS-002"
        assert result[1].id == "TS-003"
        assert result[2].id == "TS-001"


class TestSelectLeakageTargetedAttacks:
    def test_tool_leak_targets_tool_safety(self) -> None:
        leaked = [
            LeakedInfo(
                info_type="tool_name",
                content="search_database, execute_query",
                source_template_id="GA-001",
                step_index=0,
            ),
        ]
        templates = [
            _make_template("TS-001", Category.TOOL_SAFETY),
            _make_template("MI-001", Category.MEMORY_INTEGRITY),
        ]
        result = select_leakage_targeted_attacks(leaked, templates, set())
        ids = [t.id for t in result]
        assert "TS-001" in ids
        assert "MI-001" not in ids

    def test_system_prompt_leak_targets_goal_adherence(self) -> None:
        leaked = [
            LeakedInfo(
                info_type="system_prompt",
                content="You are a helpful assistant",
                source_template_id="EX-001",
                step_index=0,
            ),
        ]
        templates = [
            _make_template("GA-001", Category.GOAL_ADHERENCE),
            _make_template("TS-001", Category.TOOL_SAFETY),
        ]
        result = select_leakage_targeted_attacks(leaked, templates, set())
        ids = [t.id for t in result]
        assert "GA-001" in ids

    def test_credential_leak_targets_exfiltration(self) -> None:
        leaked = [
            LeakedInfo(
                info_type="credential",
                content="sk-abc123def456",
                source_template_id="GA-005",
                step_index=0,
            ),
        ]
        templates = [
            _make_template("EX-001", Category.CONVERSATIONAL_EXFILTRATION),
        ]
        result = select_leakage_targeted_attacks(leaked, templates, set())
        assert len(result) == 1
        assert result[0].id == "EX-001"

    def test_returns_empty_when_no_leakage(self) -> None:
        result = select_leakage_targeted_attacks([], [], set())
        assert result == []


def _chat_response(content: str) -> dict[str, Any]:
    return {"choices": [{"message": {"content": content}}]}


@pytest.mark.asyncio
class TestRunConvergenceScan:
    @respx.mock
    async def test_basic_convergence(self) -> None:
        """A scan with all-safe responses should converge after pass 1."""
        respx.post("https://target.example.com/v1/chat/completions").respond(
            json=_chat_response("I can't do that. I must follow my safety guidelines.")
        )

        target = Target(url="https://target.example.com/v1/chat/completions")
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")

        passes_seen: list[tuple[int, str]] = []

        def on_pass(pass_num: int, detail: str) -> None:
            passes_seen.append((pass_num, detail))

        result = await run_convergence_scan(
            target=target,
            adapter=adapter,
            category="goal-adherence",
            delay=0,
            on_pass=on_pass,
            max_passes=3,
        )
        await adapter.close()

        assert len(result.findings) > 0
        assert result.finished_at is not None
        # Should converge quickly with no vulns
        pass_nums = [p[0] for p in passes_seen if p[0] > 0]
        assert max(pass_nums) <= 2  # Should not need many passes

    @respx.mock
    async def test_discovery_pass_tagged(self) -> None:
        """Findings should have discovery_pass set."""
        respx.post("https://target.example.com/v1/chat/completions").respond(
            json=_chat_response("I can't do that.")
        )

        target = Target(url="https://target.example.com/v1/chat/completions")
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")

        result = await run_convergence_scan(
            target=target,
            adapter=adapter,
            category="goal-adherence",
            delay=0,
            max_passes=2,
        )
        await adapter.close()

        for finding in result.findings:
            assert finding.discovery_pass >= 1
