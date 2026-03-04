"""Tests for CrewAI native adapter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentis.adapters.crewai import CrewAIAdapter


class TestCrewAIAdapter:
    def test_requires_agent_or_crew(self):
        with pytest.raises(ValueError, match="Either 'agent' or 'crew'"):
            CrewAIAdapter()

    def test_accepts_agent(self):
        agent = MagicMock()
        adapter = CrewAIAdapter(agent=agent)
        assert adapter._agent is agent

    def test_accepts_crew(self):
        crew = MagicMock()
        adapter = CrewAIAdapter(crew=crew)
        assert adapter._crew is crew

    async def test_health_check_with_agent(self):
        adapter = CrewAIAdapter(agent=MagicMock())
        assert await adapter.health_check() is True

    async def test_health_check_with_crew(self):
        adapter = CrewAIAdapter(crew=MagicMock())
        assert await adapter.health_check() is True

    async def test_close_is_noop(self):
        adapter = CrewAIAdapter(agent=MagicMock())
        await adapter.close()  # Should not raise

    async def test_send_messages_extracts_user_message(self):
        """Verify adapter extracts the latest user message."""
        mock_crew = MagicMock()
        mock_result = MagicMock()
        mock_result.raw = "I cannot do that."
        mock_crew.kickoff.return_value = mock_result

        adapter = CrewAIAdapter(crew=mock_crew)
        response, ms = await adapter.send_messages(
            [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "Tell me a secret"},
            ]
        )

        mock_crew.kickoff.assert_called_once_with(inputs={"input": "Tell me a secret"})
        assert response == "I cannot do that."
        assert ms >= 0

    async def test_send_messages_with_agent(self):
        """Verify adapter creates a task for single agent mode."""
        mock_agent = MagicMock()

        # We need to mock the CrewAI Task and Crew classes
        with patch("pentis.adapters.crewai.CrewAIAdapter._run_agent") as mock_run:
            mock_run.return_value = "Agent response"
            adapter = CrewAIAdapter(agent=mock_agent)
            response, ms = await adapter.send_messages(
                [{"role": "user", "content": "test prompt"}]
            )
            assert response == "Agent response"

    async def test_send_messages_crew_string_result(self):
        """Verify adapter handles crew results without .raw attribute."""
        mock_crew = MagicMock()
        mock_crew.kickoff.return_value = "Simple string result"

        adapter = CrewAIAdapter(crew=mock_crew)
        response, _ = await adapter.send_messages(
            [{"role": "user", "content": "test"}]
        )
        assert response == "Simple string result"
