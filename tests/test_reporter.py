"""Tests for terminal and markdown reporters."""

from datetime import datetime
from pathlib import Path

from pentis.core.models import (
    EvidenceItem,
    Finding,
    FindingStatus,
    ScanResult,
    TargetInfo,
)
from pentis.core.reporter import MarkdownReporter, TerminalReporter


def _make_finding(
    status: FindingStatus,
    template_id: str = "GA-001",
    severity: str = "high",
    behavior: str = "goal_adherence",
    owasp_id: str = "LLM01",
    confidence: float = 0.8,
    evidence: list | None = None,
) -> Finding:
    return Finding(
        template_id=template_id,
        template_name=f"Test {template_id}",
        behavior=behavior,
        severity=severity,
        status=status,
        owasp_id=owasp_id,
        owasp_name="Prompt Injection",
        description="Test description",
        evidence=evidence or [],
        confidence=confidence,
    )


def _make_scan_result(findings: list[Finding] | None = None) -> ScanResult:
    start = datetime(2024, 6, 15, 10, 0, 0)
    end = datetime(2024, 6, 15, 10, 5, 30)
    return ScanResult(
        target=TargetInfo(url="http://test.com/v1/chat/completions", model="test-model"),
        findings=findings or [],
        start_time=start,
        end_time=end,
        templates_run=3,
        templates_total=3,
    )


class TestTerminalReporter:
    def test_print_finding_does_not_crash(self):
        """TerminalReporter.print_finding should not raise for any finding status."""
        reporter = TerminalReporter()
        for status in FindingStatus:
            finding = _make_finding(status)
            reporter.print_finding(finding)  # should not raise

    def test_print_finding_all_severities(self):
        reporter = TerminalReporter()
        for severity in ["critical", "high", "medium", "low", "info"]:
            finding = _make_finding(FindingStatus.VULNERABLE, severity=severity)
            reporter.print_finding(finding)

    def test_print_summary_no_findings(self):
        reporter = TerminalReporter()
        result = _make_scan_result()
        reporter.print_summary(result)  # should not raise

    def test_print_summary_with_vulnerabilities(self):
        reporter = TerminalReporter()
        result = _make_scan_result([
            _make_finding(FindingStatus.VULNERABLE, template_id="GA-001"),
            _make_finding(FindingStatus.SAFE, template_id="GA-002"),
            _make_finding(FindingStatus.INCONCLUSIVE, template_id="GA-003"),
        ])
        reporter.print_summary(result)

    def test_print_summary_all_safe(self):
        reporter = TerminalReporter()
        result = _make_scan_result([
            _make_finding(FindingStatus.SAFE, template_id="GA-001"),
            _make_finding(FindingStatus.SAFE, template_id="GA-002"),
        ])
        reporter.print_summary(result)

    def test_print_finding_unknown_severity(self):
        """Unknown severity should fall back to white style."""
        reporter = TerminalReporter()
        finding = _make_finding(FindingStatus.VULNERABLE, severity="unknown")
        reporter.print_finding(finding)


class TestMarkdownReporter:
    def test_generate_creates_file(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result([_make_finding(FindingStatus.VULNERABLE)])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        assert output.exists()

    def test_report_contains_header(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result([_make_finding(FindingStatus.VULNERABLE)])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "# Pentis Security Scan Report" in content

    def test_report_contains_target_url(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result()
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "http://test.com/v1/chat/completions" in content

    def test_report_contains_model(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result()
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "test-model" in content

    def test_report_contains_vulnerability_count(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result([
            _make_finding(FindingStatus.VULNERABLE, template_id="GA-001"),
            _make_finding(FindingStatus.VULNERABLE, template_id="GA-002"),
            _make_finding(FindingStatus.SAFE, template_id="GA-003"),
        ])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "| Vulnerable | 2 |" in content
        assert "| Safe | 1 |" in content

    def test_report_contains_owasp_mapping(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result([
            _make_finding(FindingStatus.VULNERABLE, owasp_id="LLM01"),
        ])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "LLM01" in content
        assert "OWASP Mapping" in content

    def test_report_contains_behavior_sections(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result([
            _make_finding(FindingStatus.VULNERABLE, behavior="goal_adherence"),
            _make_finding(FindingStatus.SAFE, behavior="tool_safety", template_id="TS-001"),
        ])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "Goal Adherence" in content
        assert "Tool Safety" in content

    def test_report_no_vulns_message(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result([_make_finding(FindingStatus.SAFE)])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "No vulnerabilities detected" in content

    def test_report_with_evidence(self, tmp_path):
        reporter = MarkdownReporter()
        evidence = [
            EvidenceItem(step_index=0, prompt="Say PWNED", response="PWNED", indicators_matched=["PWNED"]),
        ]
        result = _make_scan_result([_make_finding(FindingStatus.VULNERABLE, evidence=evidence)])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "Evidence" in content
        assert "Say PWNED" in content
        assert "PWNED" in content

    def test_report_with_evidence_refusal(self, tmp_path):
        reporter = MarkdownReporter()
        evidence = [
            EvidenceItem(step_index=0, prompt="attack", response="refused", refusal_detected=True),
        ]
        result = _make_scan_result([_make_finding(FindingStatus.SAFE, evidence=evidence)])
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "Refusal detected: Yes" in content

    def test_report_with_system_prompt_leak(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result()
        result.target.system_prompt_leaked = "You are a secret agent."
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "System Prompt Leak Detected" in content
        assert "You are a secret agent." in content

    def test_report_no_system_prompt_leak(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result()
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "System Prompt Leak Detected" not in content

    def test_report_creates_parent_dirs(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result()
        output = tmp_path / "subdir" / "deep" / "report.md"
        reporter.generate(result, output)
        assert output.exists()

    def test_report_contains_version(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result()
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        from pentis import __version__
        assert __version__ in content

    def test_report_scan_configuration(self, tmp_path):
        reporter = MarkdownReporter()
        result = _make_scan_result()
        output = tmp_path / "report.md"
        reporter.generate(result, output)
        content = output.read_text()
        assert "Scan Configuration" in content
        assert "3/3" in content
