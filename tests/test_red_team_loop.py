"""Tests for the red team loop — strategy planning, attack selection, learning."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentis.core.models import (
    AgentCapability,
    AgentProfile,
    Finding,
    LearningRecord,
    ResponseClass,
    ScanJob,
    ScheduleConfig,
    Severity,
    Verdict,
)
from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus
from pentis_service.services.red_team_loop import (
    DEFAULT_STRATEGY,
    RedTeamLoop,
    _extract_defense_patterns,
)
from pentis_service.services.regression import RegressionService


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(db_path=tmp_path / "test.db")


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


@pytest.fixture
def loop(store: Store, bus: EventBus) -> RedTeamLoop:
    regression = RegressionService(store, bus)
    return RedTeamLoop(store, bus, regression)


def test_plan_strategy_no_history(loop: RedTeamLoop) -> None:
    profile = AgentProfile(target_url="http://example.com")
    strategy = loop._plan_strategy(profile, [])
    assert strategy == DEFAULT_STRATEGY


def test_plan_strategy_low_yield(loop: RedTeamLoop) -> None:
    """Low vulnerability rate shifts toward generation and mutation."""
    profile = AgentProfile(target_url="http://example.com")
    history = [
        LearningRecord(
            cycle_id="c1",
            target_url="http://example.com",
            attacks_run=100,
            vulns_found=2,  # 2% rate
        )
    ]
    strategy = loop._plan_strategy(profile, history)
    assert strategy["generated"] > DEFAULT_STRATEGY["generated"]
    assert strategy["playbook"] < DEFAULT_STRATEGY["playbook"]


def test_plan_strategy_high_yield(loop: RedTeamLoop) -> None:
    """High vulnerability rate shifts toward mutations."""
    profile = AgentProfile(target_url="http://example.com")
    history = [
        LearningRecord(
            cycle_id="c1",
            target_url="http://example.com",
            attacks_run=100,
            vulns_found=40,  # 40% rate
        )
    ]
    strategy = loop._plan_strategy(profile, history)
    assert strategy["mutation"] > DEFAULT_STRATEGY["mutation"]


def test_is_promising_vulnerable(loop: RedTeamLoop) -> None:
    """Already vulnerable findings are not 'promising' for mutation."""
    finding = Finding(
        template_id="GA-001",
        template_name="Test",
        verdict=Verdict.VULNERABLE,
        severity=Severity.HIGH,
        category=MagicMock(),
        owasp="LLM01",
    )
    assert loop._is_promising(finding) is False


def test_is_promising_inconclusive(loop: RedTeamLoop) -> None:
    """Inconclusive findings are promising for mutation."""
    finding = Finding(
        template_id="GA-001",
        template_name="Test",
        verdict=Verdict.INCONCLUSIVE,
        severity=Severity.HIGH,
        category=MagicMock(),
        owasp="LLM01",
    )
    assert loop._is_promising(finding) is True


def test_extract_defense_patterns() -> None:
    response = "I cannot help with that due to our safety guidelines and policy restrictions."
    patterns = _extract_defense_patterns(response)
    assert "safety" in patterns
    assert "cannot" in patterns
    assert "policy" in patterns


def test_extract_defense_patterns_empty() -> None:
    response = "here is the information you requested about machine learning"
    patterns = _extract_defense_patterns(response)
    assert patterns == []


def test_compute_coverage_gaps(loop: RedTeamLoop) -> None:
    from pentis.core.models import Category

    profile = AgentProfile(
        target_url="http://example.com",
        capabilities=[
            AgentCapability(name="web_access", detected=True, probe_prompt="p"),
            AgentCapability(name="file_access", detected=True, probe_prompt="p"),
        ],
    )
    findings = [
        Finding(
            template_id="GA-001",
            template_name="Test",
            verdict=Verdict.SAFE,
            severity=Severity.HIGH,
            category=Category.GOAL_ADHERENCE,
            owasp="LLM01",
        )
    ]
    gaps = loop._compute_coverage_gaps(profile, findings)
    # Should flag untested categories
    assert any("Tool Safety" in g for g in gaps)
    # Should flag untested capabilities
    assert any("web_access" in g for g in gaps)


def test_get_tested_template_ids_empty(loop: RedTeamLoop) -> None:
    ids = loop._get_tested_template_ids("http://example.com")
    assert ids == set()
