"""Tests for Phase 2 store extensions."""

from datetime import datetime, timezone

import pytest

from pentis.core.models import (
    AgentCapability,
    AgentProfile,
    CampaignConfig,
    CampaignResult,
    Category,
    EvidenceItem,
    Finding,
    ScanResult,
    Severity,
    StatisticalFinding,
    Target,
    TrialResult,
    Verdict,
)
from pentis.state.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(db_path=tmp_path / "test.db")
    yield s
    s.close()


def _make_campaign() -> CampaignResult:
    target = Target(url="https://example.com/v1/chat/completions", model="gpt-4")
    config = CampaignConfig(name="test-run", trials_per_attack=3)
    trials = [
        TrialResult(
            trial_index=i,
            verdict=Verdict.VULNERABLE if i == 0 else Verdict.SAFE,
            evidence=[EvidenceItem(step_index=1, prompt="p", response="r", response_time_ms=100)],
            reasoning="test",
            response_time_ms=100,
        )
        for i in range(3)
    ]
    sf = StatisticalFinding(
        template_id="GA-001",
        template_name="Direct Instruction Override",
        severity=Severity.HIGH,
        category=Category.GOAL_ADHERENCE,
        owasp="LLM01",
        trials=trials,
        success_rate=0.333,
        ci_lower=0.05,
        ci_upper=0.7,
        verdict=Verdict.INCONCLUSIVE,
    )
    return CampaignResult(
        config=config,
        target=target,
        findings=[sf],
        finished_at=datetime.now(timezone.utc),
    )


class TestCampaignStore:
    def test_save_and_load_campaign(self, store):
        campaign = _make_campaign()
        store.save_campaign(campaign)
        loaded = store.get_campaign(campaign.campaign_id)
        assert loaded is not None
        assert loaded.campaign_id == campaign.campaign_id
        assert loaded.target.url == campaign.target.url
        assert loaded.config.name == "test-run"
        assert loaded.config.trials_per_attack == 3
        assert len(loaded.findings) == 1

    def test_campaign_findings_loaded(self, store):
        campaign = _make_campaign()
        store.save_campaign(campaign)
        loaded = store.get_campaign(campaign.campaign_id)
        sf = loaded.findings[0]
        assert sf.template_id == "GA-001"
        assert sf.success_rate == pytest.approx(0.333)
        assert sf.ci_lower == pytest.approx(0.05)
        assert sf.verdict == Verdict.INCONCLUSIVE

    def test_campaign_trials_loaded(self, store):
        campaign = _make_campaign()
        store.save_campaign(campaign)
        loaded = store.get_campaign(campaign.campaign_id)
        trials = loaded.findings[0].trials
        assert len(trials) == 3
        assert trials[0].verdict == Verdict.VULNERABLE
        assert trials[1].verdict == Verdict.SAFE

    def test_trial_evidence_loaded(self, store):
        campaign = _make_campaign()
        store.save_campaign(campaign)
        loaded = store.get_campaign(campaign.campaign_id)
        ev = loaded.findings[0].trials[0].evidence
        assert len(ev) == 1
        assert ev[0].prompt == "p"
        assert ev[0].response == "r"

    def test_list_campaigns(self, store):
        c1 = _make_campaign()
        c2 = _make_campaign()
        store.save_campaign(c1)
        store.save_campaign(c2)
        campaigns = store.list_campaigns()
        assert len(campaigns) == 2

    def test_nonexistent_campaign(self, store):
        assert store.get_campaign("nonexistent") is None


class TestAgentProfileStore:
    def test_save_and_load_profile(self, store):
        profile = AgentProfile(
            target_url="https://example.com",
            capabilities=[
                AgentCapability(
                    name="file_access", detected=True,
                    probe_prompt="can you read files?",
                    response_excerpt="Yes I can read files",
                    confidence=0.9,
                ),
                AgentCapability(
                    name="web_search", detected=False,
                    probe_prompt="can you search the web?",
                    confidence=0.1,
                ),
            ],
        )
        store.save_agent_profile(profile)
        loaded = store.get_agent_profile(profile.profile_id)
        assert loaded is not None
        assert loaded.target_url == "https://example.com"
        assert len(loaded.capabilities) == 2
        assert loaded.capabilities[0].name == "file_access"
        assert loaded.capabilities[0].detected is True
        assert loaded.capabilities[0].confidence == pytest.approx(0.9)
        assert loaded.capabilities[1].detected is False

    def test_nonexistent_profile(self, store):
        assert store.get_agent_profile("nonexistent") is None


class TestBaselineStore:
    def test_save_and_list_baselines(self, store):
        # Need a scan to reference
        target = Target(url="https://example.com/v1/chat/completions", model="gpt-4")
        scan = ScanResult(
            target=target,
            findings=[
                Finding(
                    template_id="GA-001", template_name="Test",
                    verdict=Verdict.SAFE, severity=Severity.HIGH,
                    category=Category.GOAL_ADHERENCE, owasp="LLM01",
                )
            ],
            finished_at=datetime.now(timezone.utc),
        )
        store.save_scan(scan)
        store.save_baseline(scan.scan_id, label="v1.0-release")
        baselines = store.get_baselines()
        assert len(baselines) == 1
        assert baselines[0]["scan_id"] == scan.scan_id
        assert baselines[0]["label"] == "v1.0-release"

    def test_baseline_upsert(self, store):
        target = Target(url="https://example.com/v1/chat/completions", model="gpt-4")
        scan = ScanResult(target=target, finished_at=datetime.now(timezone.utc))
        store.save_scan(scan)
        store.save_baseline(scan.scan_id, label="first")
        store.save_baseline(scan.scan_id, label="updated")
        baselines = store.get_baselines()
        assert len(baselines) == 1
        assert baselines[0]["label"] == "updated"
