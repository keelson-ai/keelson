"""Tests for scan diff and baseline comparison."""

from pentis.core.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
    Target,
    Verdict,
)
from pentis.diff.comparator import diff_scans, diff_from_baseline, format_diff_report


def _make_finding(tid: str, name: str, verdict: Verdict) -> Finding:
    return Finding(
        template_id=tid,
        template_name=name,
        verdict=verdict,
        severity=Severity.HIGH,
        category=Category.GOAL_ADHERENCE,
        owasp="LLM01",
    )


def _make_scan(findings: list[Finding], scan_id: str = "") -> ScanResult:
    scan = ScanResult(target=Target(url="https://test.com"), findings=findings)
    if scan_id:
        scan.scan_id = scan_id
    return scan


class TestDiffScans:
    def test_no_changes(self):
        f1 = _make_finding("GA-001", "T1", Verdict.SAFE)
        f2 = _make_finding("GA-001", "T1", Verdict.SAFE)
        diff = diff_scans(_make_scan([f1]), _make_scan([f2]))
        assert len(diff.items) == 0

    def test_regression_detected(self):
        scan_a = _make_scan([_make_finding("GA-001", "T1", Verdict.SAFE)])
        scan_b = _make_scan([_make_finding("GA-001", "T1", Verdict.VULNERABLE)])
        diff = diff_scans(scan_a, scan_b)
        assert len(diff.regressions) == 1
        assert diff.regressions[0].template_id == "GA-001"
        assert diff.regressions[0].old_verdict == Verdict.SAFE
        assert diff.regressions[0].new_verdict == Verdict.VULNERABLE

    def test_improvement_detected(self):
        scan_a = _make_scan([_make_finding("GA-001", "T1", Verdict.VULNERABLE)])
        scan_b = _make_scan([_make_finding("GA-001", "T1", Verdict.SAFE)])
        diff = diff_scans(scan_a, scan_b)
        assert len(diff.improvements) == 1

    def test_new_attack(self):
        scan_a = _make_scan([])
        scan_b = _make_scan([_make_finding("GA-001", "T1", Verdict.SAFE)])
        diff = diff_scans(scan_a, scan_b)
        assert len(diff.items) == 1
        assert diff.items[0].change_type == "new"
        assert diff.items[0].old_verdict is None

    def test_removed_attack(self):
        scan_a = _make_scan([_make_finding("GA-001", "T1", Verdict.SAFE)])
        scan_b = _make_scan([])
        diff = diff_scans(scan_a, scan_b)
        assert len(diff.items) == 1
        assert diff.items[0].change_type == "removed"

    def test_mixed_changes(self):
        scan_a = _make_scan(
            [
                _make_finding("GA-001", "T1", Verdict.SAFE),
                _make_finding("GA-002", "T2", Verdict.VULNERABLE),
                _make_finding("GA-003", "T3", Verdict.SAFE),
            ]
        )
        scan_b = _make_scan(
            [
                _make_finding("GA-001", "T1", Verdict.VULNERABLE),  # regression
                _make_finding("GA-002", "T2", Verdict.SAFE),  # improvement
                _make_finding("GA-004", "T4", Verdict.SAFE),  # new (GA-003 removed)
            ]
        )
        diff = diff_scans(scan_a, scan_b)
        assert len(diff.regressions) == 1
        assert len(diff.improvements) == 1
        new_items = [i for i in diff.items if i.change_type == "new"]
        removed_items = [i for i in diff.items if i.change_type == "removed"]
        assert len(new_items) == 1
        assert len(removed_items) == 1

    def test_inconclusive_to_vulnerable_is_regression(self):
        scan_a = _make_scan([_make_finding("GA-001", "T1", Verdict.INCONCLUSIVE)])
        scan_b = _make_scan([_make_finding("GA-001", "T1", Verdict.VULNERABLE)])
        diff = diff_scans(scan_a, scan_b)
        assert len(diff.regressions) == 1


class TestDiffFromBaseline:
    def test_uses_diff_scans(self):
        baseline = _make_scan([_make_finding("GA-001", "T1", Verdict.SAFE)])
        current = _make_scan([_make_finding("GA-001", "T1", Verdict.VULNERABLE)])
        diff = diff_from_baseline(baseline, current)
        assert len(diff.regressions) == 1


class TestFormatDiffReport:
    def test_no_changes(self):
        from pentis.core.models import ScanDiff

        diff = ScanDiff(scan_a_id="aaa", scan_b_id="bbb")
        report = format_diff_report(diff)
        assert "No changes detected" in report

    def test_regression_in_report(self):
        scan_a = _make_scan([_make_finding("GA-001", "T1", Verdict.SAFE)], scan_id="aaa")
        scan_b = _make_scan([_make_finding("GA-001", "T1", Verdict.VULNERABLE)], scan_id="bbb")
        diff = diff_scans(scan_a, scan_b)
        report = format_diff_report(diff)
        assert "Regressions" in report
        assert "GA-001" in report
        assert "SAFE" in report
        assert "VULNERABLE" in report
        assert "1 regressions" in report

    def test_summary_counts(self):
        scan_a = _make_scan(
            [
                _make_finding("GA-001", "T1", Verdict.SAFE),
                _make_finding("GA-002", "T2", Verdict.VULNERABLE),
            ],
            scan_id="aaa",
        )
        scan_b = _make_scan(
            [
                _make_finding("GA-001", "T1", Verdict.VULNERABLE),
                _make_finding("GA-002", "T2", Verdict.SAFE),
            ],
            scan_id="bbb",
        )
        diff = diff_scans(scan_a, scan_b)
        report = format_diff_report(diff)
        assert "1 regressions" in report
        assert "1 improvements" in report
