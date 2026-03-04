"""Tests for Phase 3 model additions."""

from pentis.core.models import (
    AttackChain,
    AttackStep,
    CampaignConfig,
    Category,
    ComplianceFramework,
    ConcurrencyConfig,
    LeakageSignal,
    RegressionAlert,
    ScanTier,
    Severity,
    Verdict,
)


class TestScanTierEnum:
    def test_fast(self):
        assert ScanTier.FAST.value == "fast"

    def test_deep(self):
        assert ScanTier.DEEP.value == "deep"

    def test_continuous(self):
        assert ScanTier.CONTINUOUS.value == "continuous"

    def test_from_string(self):
        assert ScanTier("fast") == ScanTier.FAST


class TestComplianceFrameworkEnum:
    def test_owasp(self):
        assert ComplianceFramework.OWASP_LLM_TOP_10.value == "owasp-llm-top10"

    def test_nist(self):
        assert ComplianceFramework.NIST_AI_RMF.value == "nist-ai-rmf"

    def test_eu_ai_act(self):
        assert ComplianceFramework.EU_AI_ACT.value == "eu-ai-act"

    def test_iso_42001(self):
        assert ComplianceFramework.ISO_42001.value == "iso-42001"

    def test_soc2(self):
        assert ComplianceFramework.SOC2.value == "soc2"


class TestConcurrencyConfig:
    def test_defaults(self):
        config = ConcurrencyConfig()
        assert config.max_concurrent_trials == 5
        assert config.early_termination_threshold == 3

    def test_custom_values(self):
        config = ConcurrencyConfig(max_concurrent_trials=10, early_termination_threshold=5)
        assert config.max_concurrent_trials == 10
        assert config.early_termination_threshold == 5


class TestCampaignConfigConcurrency:
    def test_default_concurrency(self):
        config = CampaignConfig()
        assert config.concurrency.max_concurrent_trials == 5
        assert config.concurrency.early_termination_threshold == 3

    def test_custom_concurrency(self):
        config = CampaignConfig(
            concurrency=ConcurrencyConfig(max_concurrent_trials=10)
        )
        assert config.concurrency.max_concurrent_trials == 10


class TestLeakageSignal:
    def test_creation(self):
        signal = LeakageSignal(
            step_index=2,
            signal_type="progressive_disclosure",
            severity="high",
            description="Response grew 5x",
            confidence=0.85,
        )
        assert signal.step_index == 2
        assert signal.signal_type == "progressive_disclosure"
        assert signal.severity == "high"
        assert signal.confidence == 0.85


class TestRegressionAlert:
    def test_creation(self):
        alert = RegressionAlert(
            template_id="GA-001",
            alert_severity="critical",
            change_type="regression",
            description="SAFE → VULNERABLE",
            old_verdict=Verdict.SAFE,
            new_verdict=Verdict.VULNERABLE,
            attack_severity=Severity.HIGH,
        )
        assert alert.alert_severity == "critical"
        assert alert.old_verdict == Verdict.SAFE
        assert alert.new_verdict == Verdict.VULNERABLE


class TestAttackChain:
    def test_creation(self):
        chain = AttackChain(
            name="Test Chain",
            capabilities=["file_access", "web_access"],
            steps=[
                AttackStep(index=1, prompt="Step 1"),
                AttackStep(index=2, prompt="Step 2"),
            ],
            severity=Severity.CRITICAL,
            category=Category.AGENTIC_SECURITY,
            owasp="LLM08",
            description="Test chain description",
        )
        assert chain.name == "Test Chain"
        assert len(chain.capabilities) == 2
        assert len(chain.steps) == 2
        assert chain.chain_id  # Auto-generated
