"""Tests for the scanner pipeline."""

from pathlib import Path
from typing import Any

import pytest
import respx

from pentis.adapters.openai import OpenAIAdapter
from pentis.core.models import Finding, Target
from pentis.core.scanner import run_scan


def _chat_response(content: str) -> dict[str, Any]:
    return {"choices": [{"message": {"content": content}}]}


ATTACKS_DIR = Path(__file__).resolve().parents[1] / "attacks"


@pytest.mark.asyncio
class TestScanner:
    @respx.mock
    async def test_scan_single_category(self, tmp_path: Path) -> None:
        """Scan just goal-adherence with a mock target that always refuses."""
        respx.post("https://target.example.com/v1/chat/completions").respond(  # type: ignore[reportUnknownMemberType]
            json=_chat_response("I can't do that. I must follow my safety guidelines.")
        )
        target = Target(url="https://target.example.com/v1/chat/completions")
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")

        result = await run_scan(
            target=target,
            adapter=adapter,
            attacks_dir=ATTACKS_DIR,
            category="goal-adherence",
            delay=0,
        )
        await adapter.close()

        assert len(result.findings) == 37
        assert result.target.url == "https://target.example.com/v1/chat/completions"
        assert result.finished_at is not None

    @respx.mock
    async def test_scan_progress_callback(self, tmp_path: Path) -> None:
        respx.post("https://target.example.com/v1/chat/completions").respond(  # type: ignore[reportUnknownMemberType]
            json=_chat_response("I can't do that.")
        )
        target = Target(url="https://target.example.com/v1/chat/completions")
        adapter = OpenAIAdapter("https://target.example.com/v1/chat/completions")

        progress: list[tuple[str, int, int]] = []

        def on_finding(finding: Finding, current: int, total: int) -> None:
            progress.append((finding.template_id, current, total))

        await run_scan(
            target=target,
            adapter=adapter,
            attacks_dir=ATTACKS_DIR,
            category="memory-integrity",
            delay=0,
            on_finding=on_finding,
        )
        await adapter.close()

        assert len(progress) == 16
        assert progress[0][1] == 1  # first
        assert progress[-1][1] == 16  # last
        assert progress[-1][2] == 16  # total
