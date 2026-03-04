"""Tests for compliance report generation."""

from pentis.core.compliance import (
    ComplianceFramework,
    PCI_DSS_V4_CONTROLS,
    generate_compliance_report,
    _control_status,  # type: ignore[reportPrivateUsage]
    _map_findings_to_owasp,  # type: ignore[reportPrivateUsage]
)
from pentis.core.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
    Target,
    Verdict,
)


def _make_finding(
    template_id: str,
    verdict: Verdict,
    severity: Severity = Severity.HIGH,
    category: Category = Category.GOAL_ADHERENCE,
    owasp: str = "LLM01 — Prompt Injection",
) -> Finding:
    return Finding(
        template_id=template_id,
        template_name=f"Attack {template_id}",
        verdict=verdict,
        severity=severity,
        category=category,
        owasp=owasp,
    )


def _make_scan(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        scan_id="test-scan-123",
        target=Target(url="https://example.com", model="gpt-4"),
        findings=findings,
    )


class TestControlStatus:
    def test_pass(self):
        findings = [_make_finding("GA-001", Verdict.SAFE)]
        assert _control_status(findings) == "PASS"

    def test_fail(self):
        findings = [_make_finding("GA-001", Verdict.VULNERABLE)]
        assert _control_status(findings) == "FAIL"

    def test_partial(self):
        findings = [
            _make_finding("GA-001", Verdict.SAFE),
            _make_finding("GA-002", Verdict.INCONCLUSIVE),
        ]
        assert _control_status(findings) == "PARTIAL"

    def test_not_tested(self):
        assert _control_status([]) == "NOT TESTED"


class TestMapFindingsToOwasp:
    def test_direct_owasp_mapping(self):
        findings = [
            _make_finding("GA-001", Verdict.VULNERABLE, owasp="LLM01 — Prompt Injection"),
        ]
        mapping = _map_findings_to_owasp(findings)
        assert len(mapping["LLM01"]) == 1
        assert mapping["LLM01"][0].template_id == "GA-001"

    def test_prefix_fallback(self):
        findings = [
            _make_finding("GA-001", Verdict.VULNERABLE, owasp="Unknown"),
        ]
        mapping = _map_findings_to_owasp(findings)
        # GA- prefix maps to LLM01
        assert len(mapping["LLM01"]) == 1


class TestGenerateComplianceReport:
    def test_owasp_report_structure(self):
        scan = _make_scan(
            [
                _make_finding("GA-001", Verdict.VULNERABLE),
                _make_finding("GA-002", Verdict.SAFE),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.OWASP_LLM_TOP_10)
        assert "OWASP LLM Top 10" in report
        assert "GA-001" in report
        assert "FAIL" in report
        assert "Recommendations" in report

    def test_owasp_report_all_safe(self):
        scan = _make_scan(
            [
                _make_finding("GA-001", Verdict.SAFE),
                _make_finding("GA-002", Verdict.SAFE),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.OWASP_LLM_TOP_10)
        assert "passed" in report.lower() or "PASS" in report

    def test_nist_report(self):
        scan = _make_scan([_make_finding("GA-001", Verdict.VULNERABLE)])
        report = generate_compliance_report(scan, ComplianceFramework.NIST_AI_RMF)
        assert "NIST AI RMF" in report
        assert "Govern" in report or "GOVERN" in report
        assert "Measure" in report or "MEASURE" in report

    def test_eu_ai_act_report(self):
        scan = _make_scan([_make_finding("GA-001", Verdict.VULNERABLE)])
        report = generate_compliance_report(scan, ComplianceFramework.EU_AI_ACT)
        assert "EU AI Act" in report
        assert "Article" in report

    def test_iso_42001_report(self):
        scan = _make_scan([_make_finding("GA-001", Verdict.SAFE)])
        report = generate_compliance_report(scan, ComplianceFramework.ISO_42001)
        assert "ISO 42001" in report

    def test_soc2_report(self):
        scan = _make_scan(
            [
                _make_finding("TS-001", Verdict.VULNERABLE, category=Category.TOOL_SAFETY),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.SOC2)
        assert "SOC2" in report

    def test_empty_scan(self):
        scan = _make_scan([])
        report = generate_compliance_report(scan, ComplianceFramework.OWASP_LLM_TOP_10)
        assert "NOT TESTED" in report

    def test_coverage_percentage(self):
        scan = _make_scan(
            [
                _make_finding("GA-001", Verdict.VULNERABLE, owasp="LLM01 — Prompt Injection"),
                _make_finding(
                    "TS-001",
                    Verdict.SAFE,
                    owasp="LLM02 — Insecure Output",
                    category=Category.TOOL_SAFETY,
                ),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.OWASP_LLM_TOP_10)
        assert "Coverage" in report

    def test_pci_dss_report(self):
        scan = _make_scan(
            [
                _make_finding(
                    "PB-001",
                    Verdict.VULNERABLE,
                    category=Category.PERMISSION_BOUNDARIES,
                    owasp="LLM02 — Insecure Output Handling",
                ),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.PCI_DSS_V4)
        assert "PCI DSS 4.0" in report
        assert "FAIL" in report
        assert "PB-001" in report

    def test_pci_dss_report_all_safe(self):
        scan = _make_scan(
            [
                _make_finding(
                    "ES-001",
                    Verdict.SAFE,
                    category=Category.EXECUTION_SAFETY,
                    owasp="LLM06 — Sensitive Information Disclosure",
                ),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.PCI_DSS_V4)
        assert "PCI DSS 4.0" in report
        assert "passed" in report.lower()

    def test_pci_dss_controls_exist(self):
        assert "6.2" in PCI_DSS_V4_CONTROLS
        assert "6.3" in PCI_DSS_V4_CONTROLS
        assert "6.4" in PCI_DSS_V4_CONTROLS
        assert "11.3" in PCI_DSS_V4_CONTROLS


class TestNewCategoryMappings:
    """Test that new categories map correctly across frameworks."""

    def test_owasp_permission_boundaries(self):
        findings = [
            _make_finding(
                "PB-001",
                Verdict.VULNERABLE,
                category=Category.PERMISSION_BOUNDARIES,
                owasp="Unknown",
            ),
        ]
        mapping = _map_findings_to_owasp(findings)
        assert len(mapping["LLM02"]) == 1  # PB- prefix → LLM02

    def test_owasp_delegation_integrity(self):
        findings = [
            _make_finding(
                "DI-001",
                Verdict.VULNERABLE,
                category=Category.DELEGATION_INTEGRITY,
                owasp="Unknown",
            ),
        ]
        mapping = _map_findings_to_owasp(findings)
        assert len(mapping["LLM08"]) == 1  # DI- prefix → LLM08

    def test_owasp_execution_safety(self):
        findings = [
            _make_finding(
                "ES-001", Verdict.VULNERABLE, category=Category.EXECUTION_SAFETY, owasp="Unknown"
            ),
        ]
        mapping = _map_findings_to_owasp(findings)
        assert len(mapping["LLM06"]) == 1  # ES- prefix → LLM06

    def test_owasp_session_isolation(self):
        findings = [
            _make_finding(
                "SI-001", Verdict.VULNERABLE, category=Category.SESSION_ISOLATION, owasp="Unknown"
            ),
        ]
        mapping = _map_findings_to_owasp(findings)
        assert len(mapping["LLM05"]) == 1  # SI- prefix → LLM05

    def test_eu_ai_act_new_articles(self):
        scan = _make_scan(
            [
                _make_finding(
                    "DI-001",
                    Verdict.VULNERABLE,
                    category=Category.DELEGATION_INTEGRITY,
                    owasp="LLM08",
                ),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.EU_AI_ACT)
        assert "Article 9" in report
        assert "Article 14" in report

    def test_nist_category_mapping(self):
        scan = _make_scan(
            [
                _make_finding(
                    "PB-001",
                    Verdict.VULNERABLE,
                    category=Category.PERMISSION_BOUNDARIES,
                    owasp="LLM02",
                ),
            ]
        )
        report = generate_compliance_report(scan, ComplianceFramework.NIST_AI_RMF)
        assert "NIST AI RMF" in report
        # MEASURE gets all findings, GOVERN gets PB findings
        assert "FAIL" in report
