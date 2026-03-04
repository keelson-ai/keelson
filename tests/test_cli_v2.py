"""Tests for Phase 2 CLI commands."""

from datetime import datetime, timezone

from pathlib import Path

from typer.testing import CliRunner

from pentis.cli import app
from pentis.core.models import (
    Category,
    Finding,
    ScanResult,
    Severity,
    Target,
    Verdict,
)
from pentis.state.store import Store

runner = CliRunner()


class TestCampaignCommand:
    def test_campaign_missing_config(self):
        result = runner.invoke(app, ["campaign", "/nonexistent/config.toml"])
        assert result.exit_code != 0

    def test_campaign_help(self):
        result = runner.invoke(app, ["campaign", "--help"])
        assert result.exit_code == 0
        assert "TOML" in result.output or "config" in result.output.lower()


class TestDiscoverCommand:
    def test_discover_help(self):
        result = runner.invoke(app, ["discover", "--help"])
        assert result.exit_code == 0
        assert "endpoint" in result.output.lower() or "url" in result.output.lower()


class TestDiffCommand:
    def test_diff_help(self):
        result = runner.invoke(app, ["diff", "--help"])
        assert result.exit_code == 0

    def test_diff_nonexistent_scans(self):
        result = runner.invoke(app, ["diff", "nonexistent-a", "nonexistent-b"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


class TestEvolveCommand:
    def test_evolve_help(self):
        result = runner.invoke(app, ["evolve", "--help"])
        assert result.exit_code == 0
        assert "mutate" in result.output.lower() or "attack" in result.output.lower()

    def test_evolve_nonexistent_attack(self):
        result = runner.invoke(app, ["evolve", "http://test", "NONEXISTENT-999"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


class TestBaselineCommand:
    def test_baseline_help(self):
        result = runner.invoke(app, ["baseline", "--help"])
        assert result.exit_code == 0

    def test_baseline_nonexistent_scan(self):
        result = runner.invoke(app, ["baseline", "nonexistent-scan"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_baseline_set(self, tmp_path: Path) -> None:
        # Create a scan first
        store = Store(db_path=tmp_path / "test.db")
        target = Target(url="https://example.com/v1/chat/completions", model="gpt-4")
        scan = ScanResult(
            target=target,
            findings=[
                Finding(
                    template_id="GA-001",
                    template_name="Test",
                    verdict=Verdict.SAFE,
                    severity=Severity.HIGH,
                    category=Category.GOAL_ADHERENCE,
                    owasp="LLM01",
                )
            ],
            finished_at=datetime.now(timezone.utc),
        )
        store.save_scan(scan)
        store.save_baseline(scan.scan_id, label="test-baseline")
        baselines = store.get_baselines()
        store.close()
        assert len(baselines) == 1
        assert baselines[0]["label"] == "test-baseline"


class TestFailGates:
    """Test _check_fail_gates logic for CI/CD fail conditions."""

    def test_fail_on_vuln_with_vulns(self) -> None:
        import click.exceptions
        import pytest
        from pentis.cli import _check_fail_gates  # type: ignore[reportPrivateUsage]

        with pytest.raises(click.exceptions.Exit):
            _check_fail_gates(vuln_count=1, total=100, fail_on_vuln=True, threshold=0.0)

    def test_fail_on_vuln_no_vulns(self) -> None:
        from pentis.cli import _check_fail_gates  # type: ignore[reportPrivateUsage]

        # Should not raise
        _check_fail_gates(vuln_count=0, total=100, fail_on_vuln=True, threshold=0.0)

    def test_threshold_exceeded(self) -> None:
        import click.exceptions
        import pytest
        from pentis.cli import _check_fail_gates  # type: ignore[reportPrivateUsage]

        with pytest.raises(click.exceptions.Exit):
            _check_fail_gates(vuln_count=20, total=100, fail_on_vuln=False, threshold=0.1)

    def test_threshold_not_exceeded(self) -> None:
        from pentis.cli import _check_fail_gates  # type: ignore[reportPrivateUsage]

        # 5% < 10% threshold — should not raise
        _check_fail_gates(vuln_count=5, total=100, fail_on_vuln=False, threshold=0.1)

    def test_fail_on_vuln_independent_of_threshold(self) -> None:
        """--fail-on-vuln should fail even when rate is below --fail-threshold."""
        import click.exceptions
        import pytest
        from pentis.cli import _check_fail_gates  # type: ignore[reportPrivateUsage]

        with pytest.raises(click.exceptions.Exit):
            # 1 vuln out of 100 = 1% rate, below 50% threshold
            # But --fail-on-vuln should still trigger
            _check_fail_gates(vuln_count=1, total=100, fail_on_vuln=True, threshold=0.5)

    def test_neither_flag_does_not_fail(self) -> None:
        from pentis.cli import _check_fail_gates  # type: ignore[reportPrivateUsage]

        # No flags — should never fail even with vulns
        _check_fail_gates(vuln_count=50, total=100, fail_on_vuln=False, threshold=0.0)


class TestExistingCommandsStillWork:
    """Verify Phase 1 commands are not broken."""

    def test_list_attacks(self):
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "GA-001" in result.output

    def test_list_attacks_filtered(self):
        result = runner.invoke(app, ["list", "--category", "tool-safety"])
        assert result.exit_code == 0
        assert "TS-001" in result.output

    def test_history_works(self):
        result = runner.invoke(app, ["history"])
        assert result.exit_code == 0
