"""Tests for the CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from pentis.cli import app

runner = CliRunner()


class TestCLIVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "pentis 0.1.0" in result.output

    def test_version_short_flag(self):
        result = runner.invoke(app, ["-v"])
        assert result.exit_code == 0
        assert "pentis 0.1.0" in result.output


class TestCLIList:
    def test_list_shows_templates(self):
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0
        assert "GA-001" in result.output
        assert "28 templates loaded" in result.output

    def test_list_filter_goal_adherence(self):
        result = runner.invoke(app, ["list", "--behavior", "goal_adherence"])
        assert result.exit_code == 0
        assert "GA-001" in result.output
        assert "10 templates loaded" in result.output

    def test_list_filter_tool_safety(self):
        result = runner.invoke(app, ["list", "--behavior", "tool_safety"])
        assert result.exit_code == 0
        assert "TS-001" in result.output
        assert "10 templates loaded" in result.output

    def test_list_filter_memory_integrity(self):
        result = runner.invoke(app, ["list", "--behavior", "memory_integrity"])
        assert result.exit_code == 0
        assert "MI-001" in result.output
        assert "8 templates loaded" in result.output

    def test_list_filter_nonexistent_behavior(self):
        result = runner.invoke(app, ["list", "--behavior", "nonexistent"])
        assert result.exit_code == 0
        assert "No templates found" in result.output


class TestCLIInit:
    def test_init_creates_config(self, tmp_path):
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert "Created config" in result.output
        config = tmp_path / "pentis.yaml"
        assert config.exists()
        content = config.read_text()
        assert "target:" in content
        assert "behaviors:" in content

    def test_init_refuses_existing_config(self, tmp_path):
        config = tmp_path / "pentis.yaml"
        config.write_text("existing")
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_init_creates_nested_dirs(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        result = runner.invoke(app, ["init", str(nested)])
        assert result.exit_code == 0
        assert (nested / "pentis.yaml").exists()


class TestCLIScan:
    def test_scan_requires_url(self):
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0
        assert "Missing" in result.output or "required" in result.output.lower()

    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--url" in result.output
        assert "--api-key" in result.output
        assert "--model" in result.output
        assert "--behaviors" in result.output
        assert "--timeout" in result.output
        assert "--rate-limit" in result.output
        assert "--no-banner" in result.output


class TestCLINoArgs:
    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer with no_args_is_help=True exits with code 0 or 2
        assert result.exit_code in (0, 2)
        assert "scan" in result.output
        assert "list" in result.output
        assert "init" in result.output
