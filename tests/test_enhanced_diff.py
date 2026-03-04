"""Tests for enhanced regression alerts and campaign diff."""

from pentis.core.models import (
    Category,
    CampaignConfig,
    CampaignResult,
    Finding,
    ScanDiffItem,
    ScanResult,
    Severity,
    StatisticalFinding,
    Target,
    Verdict,
)
from pentis.diff.comparator import (
    classify_alert_severity,
    diff_campaigns,
    enhanced_diff_scans,
)


def _make_finding(
    template_id: str, verdict: Verdict, severity: Severity = Severity.HIGH
) -> Finding:
    return Finding(
        template_id=template_id,
        template_name=f"Attack {template_id}",
        verdict=verdict,
        severity=severity,
        category=Category.GOAL_ADHERENCE,
        owasp="LLM01",
    )


def _make_scan(scan_id: str, findings: list[Finding]) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        target=Target(url="https://example.com"),
        findings=findings,
    )


class TestClassifyAlertSeverity:
    def test_safe_to_vuln_critical_attack(self):
        item = ScanDiffItem(
            template_id="GA-001",
            template_name="Test",
            old_verdict=Verdict.SAFE,
            new_verdict=Verdict.VULNERABLE,
            change_type="regression",
        )
        assert classify_alert_severity(item, Severity.CRITICAL) == "critical"

    def test_safe_to_vuln_high_attack(self):
        item = ScanDiffItem(
            template_id="GA-001",
            template_name="Test",
            old_verdict=Verdict.SAFE,
            new_verdict=Verdict.VULNERABLE,
            change_type="regression",
        )
        assert classify_alert_severity(item, Severity.HIGH) == "critical"

    def test_safe_to_vuln_medium_attack(self):
        item = ScanDiffItem(
            template_id="GA-001",
            template_name="Test",
            old_verdict=Verdict.SAFE,
            new_verdict=Verdict.VULNERABLE,
            change_type="regression",
        )
        assert classify_alert_severity(item, Severity.MEDIUM) == "high"

    def test_new_vulnerable(self):
        item = ScanDiffItem(
            template_id="GA-001",
            template_name="Test",
            old_verdict=None,
            new_verdict=Verdict.VULNERABLE,
            change_type="new",
        )
        assert classify_alert_severity(item) == "high"

    def test_inconclusive_to_vuln(self):
        item = ScanDiffItem(
            template_id="GA-001",
            template_name="Test",
            old_verdict=Verdict.INCONCLUSIVE,
            new_verdict=Verdict.VULNERABLE,
            change_type="regression",
        )
        assert classify_alert_severity(item) == "medium"

    def test_safe_to_inconclusive(self):
        item = ScanDiffItem(
            template_id="GA-001",
            template_name="Test",
            old_verdict=Verdict.SAFE,
            new_verdict=Verdict.INCONCLUSIVE,
            change_type="regression",
        )
        assert classify_alert_severity(item) == "low"


class TestEnhancedDiffScans:
    def test_regression_produces_alert(self):
        scan_a = _make_scan("a", [_make_finding("GA-001", Verdict.SAFE)])
        scan_b = _make_scan("b", [_make_finding("GA-001", Verdict.VULNERABLE)])
        diff, alerts = enhanced_diff_scans(scan_a, scan_b)
        assert len(alerts) == 1
        assert alerts[0].alert_severity == "critical"
        assert alerts[0].template_id == "GA-001"

    def test_improvement_no_alert(self):
        scan_a = _make_scan("a", [_make_finding("GA-001", Verdict.VULNERABLE)])
        scan_b = _make_scan("b", [_make_finding("GA-001", Verdict.SAFE)])
        diff, alerts = enhanced_diff_scans(scan_a, scan_b)
        assert len(alerts) == 0

    def test_no_change_no_alert(self):
        scan_a = _make_scan("a", [_make_finding("GA-001", Verdict.SAFE)])
        scan_b = _make_scan("b", [_make_finding("GA-001", Verdict.SAFE)])
        diff, alerts = enhanced_diff_scans(scan_a, scan_b)
        assert len(alerts) == 0

    def test_alerts_sorted_by_severity(self):
        scan_a = _make_scan(
            "a",
            [
                _make_finding("GA-001", Verdict.SAFE, Severity.HIGH),
                _make_finding("GA-002", Verdict.INCONCLUSIVE, Severity.MEDIUM),
            ],
        )
        scan_b = _make_scan(
            "b",
            [
                _make_finding("GA-001", Verdict.VULNERABLE, Severity.HIGH),
                _make_finding("GA-002", Verdict.VULNERABLE, Severity.MEDIUM),
            ],
        )
        diff, alerts = enhanced_diff_scans(scan_a, scan_b)
        assert len(alerts) == 2
        assert alerts[0].alert_severity == "critical"
        assert alerts[1].alert_severity == "medium"


class TestDiffCampaigns:
    def _make_stat_finding(
        self, tid: str, verdict: Verdict, rate: float, severity: Severity = Severity.HIGH
    ) -> StatisticalFinding:
        return StatisticalFinding(
            template_id=tid,
            template_name=f"Attack {tid}",
            severity=severity,
            category=Category.GOAL_ADHERENCE,
            owasp="LLM01",
            success_rate=rate,
            verdict=verdict,
        )

    def _make_campaign(self, cid: str, findings: list[StatisticalFinding]) -> CampaignResult:
        return CampaignResult(
            campaign_id=cid,
            config=CampaignConfig(),
            target=Target(url="https://example.com"),
            findings=findings,
        )

    def test_safe_to_vuln_regression(self):
        ca = self._make_campaign("a", [self._make_stat_finding("GA-001", Verdict.SAFE, 0.0)])
        cb = self._make_campaign("b", [self._make_stat_finding("GA-001", Verdict.VULNERABLE, 0.8)])
        alerts = diff_campaigns(ca, cb)
        assert len(alerts) == 1
        assert alerts[0].alert_severity == "critical"

    def test_rate_increase(self):
        ca = self._make_campaign(
            "a", [self._make_stat_finding("GA-001", Verdict.INCONCLUSIVE, 0.3)]
        )
        cb = self._make_campaign(
            "b", [self._make_stat_finding("GA-001", Verdict.INCONCLUSIVE, 0.6)]
        )
        alerts = diff_campaigns(ca, cb)
        assert len(alerts) >= 1
        assert any(a.change_type == "rate_increase" for a in alerts)

    def test_new_vulnerable_attack(self):
        ca = self._make_campaign("a", [])
        cb = self._make_campaign("b", [self._make_stat_finding("GA-001", Verdict.VULNERABLE, 0.9)])
        alerts = diff_campaigns(ca, cb)
        assert len(alerts) == 1
        assert alerts[0].change_type == "new_vulnerable"

    def test_no_change(self):
        finding = self._make_stat_finding("GA-001", Verdict.SAFE, 0.0)
        ca = self._make_campaign("a", [finding])
        cb = self._make_campaign("b", [finding])
        alerts = diff_campaigns(ca, cb)
        assert len(alerts) == 0
