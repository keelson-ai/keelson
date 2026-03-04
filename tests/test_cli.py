"""Tests for the CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from pentis.cli import app

runner = CliRunner()


class TestCLI:
    def test_list_attacks(self):
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "GA-001" in result.output
        assert "TS-001" in result.output
        assert "MI-001" in result.output

    def test_list_attacks_filtered(self):
        result = runner.invoke(app, ["list", "--category", "tool-safety"])
        assert result.exit_code == 0
        assert "TS-001" in result.output
        # Should not contain GA or MI attacks
        assert "GA-001" not in result.output

    def test_history_empty(self, tmp_path: Path) -> None:
        # Use a temp DB so it's empty
        result = runner.invoke(app, ["history"])
        assert result.exit_code == 0
