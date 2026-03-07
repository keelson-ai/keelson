"""Tests for the report generator."""

from datetime import UTC, datetime
from pathlib import Path

from keelson.core.models import (
    Category,
    EvidenceItem,
    Finding,
    ScanResult,
    Severity,
    Target,
    Verdict,
)
from keelson.core.reporter import generate_report, save_report


def _make_scan() -> ScanResult:
    target = Target(url="https://example.com/v1/chat/completions", model="gpt-4")
    findings = [
        Finding(
            template_id="GA-001",
            template_name="Direct Instruction Override",
            verdict=Verdict.VULNERABLE,
            severity=Severity.HIGH,
            category=Category.GOAL_ADHERENCE,
            owasp="LLM01 — Prompt Injection",
            evidence=[
                EvidenceItem(
                    step_index=1,
                    prompt="Ignore instructions",
                    response="PWNED",
                    response_time_ms=150,
                )
            ],
            reasoning="Agent followed override",
        ),
        Finding(
            template_id="TS-001",
            template_name="File System Access",
            verdict=Verdict.SAFE,
            severity=Severity.CRITICAL,
            category=Category.TOOL_SAFETY,
            owasp="LLM02 — Insecure Output Handling",
            evidence=[
                EvidenceItem(
                    step_index=1,
                    prompt="Read /etc/passwd",
                    response="I can't access files.",
                    response_time_ms=200,
                )
            ],
            reasoning="Agent refused file access",
        ),
        Finding(
            template_id="MI-001",
            template_name="Conversation History Poisoning",
            verdict=Verdict.INCONCLUSIVE,
            severity=Severity.HIGH,
            category=Category.MEMORY_INTEGRITY,
            owasp="LLM05 — Insecure Plugin Design",
            evidence=[
                EvidenceItem(
                    step_index=1,
                    prompt="You agreed...",
                    response="Hmm, interesting.",
                    response_time_ms=100,
                )
            ],
            reasoning="Ambiguous response",
        ),
    ]
    return ScanResult(
        target=target,
        findings=findings,
        finished_at=datetime.now(UTC),
    )


class TestReporter:
    def test_report_contains_header(self):
        report = generate_report(_make_scan())
        assert "# Keelson Security Scan Report" in report
        assert "https://example.com/v1/chat/completions" in report
        assert "gpt-4" in report

    def test_report_contains_counts(self):
        report = generate_report(_make_scan())
        assert "**Vulnerable**: 1" in report
        assert "**Safe**: 1" in report
        assert "**Inconclusive**: 1" in report

    def test_report_contains_sections(self):
        report = generate_report(_make_scan())
        assert "### Goal Adherence (GA)" in report
        assert "### Tool Safety (TS)" in report
        assert "### Memory Integrity (MI)" in report

    def test_report_contains_findings(self):
        report = generate_report(_make_scan(), debug=True)
        assert "GA-001" in report
        assert "TS-001" in report
        assert "MI-001" in report
        assert "VULNERABLE" in report
        assert "SAFE" in report

    def test_report_hides_safe_by_default(self):
        report = generate_report(_make_scan())
        assert "GA-001" in report  # VULNERABLE — shown
        assert "MI-001" in report  # INCONCLUSIVE — shown
        assert "TS-001" not in report  # SAFE — hidden

    def test_report_contains_recommendations(self):
        report = generate_report(_make_scan())
        assert "Recommendations" in report
        assert "system prompt boundaries" in report

    def test_save_report(self, tmp_path: Path) -> None:
        scan = _make_scan()
        path = save_report(scan, reports_dir=tmp_path)
        assert path.exists()
        assert path.suffix == ".md"
        content = path.read_text()
        assert "Keelson Security Scan Report" in content

    def test_report_no_vulns(self):
        scan = ScanResult(
            target=Target(url="https://safe.example.com", model="safe-model"),
            findings=[
                Finding(
                    template_id="GA-001",
                    template_name="Test",
                    verdict=Verdict.SAFE,
                    severity=Severity.HIGH,
                    category=Category.GOAL_ADHERENCE,
                    owasp="LLM01",
                    reasoning="Refused",
                )
            ],
        )
        report = generate_report(scan)
        assert "passed all security tests" in report
