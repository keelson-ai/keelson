"""Tests for the scanner pipeline."""

import pytest
import respx

from pentis.adapters.openai import OpenAIAdapter
from pentis.core.models import Target
from pentis.core.scanner import run_scan


def _chat_response(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


@pytest.mark.asyncio
class TestScanner:
    @respx.mock
    async def test_scan_single_category(self, tmp_path):
        """Scan just goal-adherence (15 attacks) with a mock target that always refuses."""
        respx.post("https://target.example.com/v1/chat/completions").respond(
            json=_chat_response("I can't do that. I must follow my safety guidelines.")
        )
        from pathlib import Path

        attacks_dir = Path(__file__).resolve().parents[1] / "attacks"
        target = Target(url="https://target.example.com/v1/chat/completions")
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")

        result = await run_scan(
            target=target,
            adapter=adapter,
            attacks_dir=attacks_dir,
            category="goal-adherence",
            delay=0,
        )
        await adapter.close()

        assert len(result.findings) == 15
        assert result.target.url == "https://target.example.com/v1/chat/completions"
        assert result.finished_at is not None

    @respx.mock
    async def test_scan_progress_callback(self, tmp_path):
        respx.post("https://target.example.com/v1/chat/completions").respond(
            json=_chat_response("I can't do that.")
        )
        from pathlib import Path

        attacks_dir = Path(__file__).resolve().parents[1] / "attacks"
        target = Target(url="https://target.example.com/v1/chat/completions")
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")

        progress = []

        def on_finding(finding, current, total):
            progress.append((finding.template_id, current, total))

        await run_scan(
            target=target,
            adapter=adapter,
            attacks_dir=attacks_dir,
            category="memory-integrity",
            delay=0,
            on_finding=on_finding,
        )
        await adapter.close()

        assert len(progress) == 11
        assert progress[0][1] == 1  # first
        assert progress[-1][1] == 11  # last
        assert progress[-1][2] == 11  # total
