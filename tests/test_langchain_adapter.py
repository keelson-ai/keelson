"""Tests for LangChain native adapter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from pentis.adapters.langchain import LangChainAdapter


class TestLangChainAdapter:
    def test_requires_agent_or_runnable(self):
        with pytest.raises(ValueError, match="Either 'agent' or 'runnable'"):
            LangChainAdapter()

    def test_accepts_agent(self):
        agent = MagicMock()
        adapter = LangChainAdapter(agent=agent)
        assert adapter._agent is agent

    def test_accepts_runnable(self):
        runnable = MagicMock()
        adapter = LangChainAdapter(runnable=runnable)
        assert adapter._runnable is runnable

    async def test_health_check(self):
        adapter = LangChainAdapter(agent=MagicMock())
        assert await adapter.health_check() is True

    async def test_close_is_noop(self):
        adapter = LangChainAdapter(agent=MagicMock())
        await adapter.close()

    async def test_send_messages_with_dict_result(self):
        """Verify adapter handles dict results with output key."""
        mock_agent = MagicMock()
        mock_agent.ainvoke = AsyncMock(return_value={"output": "Agent response"})

        adapter = LangChainAdapter(agent=mock_agent)
        response, ms = await adapter.send_messages(
            [{"role": "user", "content": "test prompt"}]
        )

        mock_agent.ainvoke.assert_called_once_with({"input": "test prompt"})
        assert response == "Agent response"
        assert ms >= 0

    async def test_send_messages_with_string_result(self):
        """Verify adapter handles string results."""
        mock_runnable = MagicMock()
        mock_runnable.ainvoke = AsyncMock(return_value="Direct string response")

        adapter = LangChainAdapter(runnable=mock_runnable)
        response, _ = await adapter.send_messages(
            [{"role": "user", "content": "test"}]
        )
        assert response == "Direct string response"

    async def test_send_messages_with_content_attribute(self):
        """Verify adapter handles objects with .content attribute (BaseMessage)."""
        mock_msg = MagicMock()
        mock_msg.content = "Message content"

        mock_chain = MagicMock()
        mock_chain.ainvoke = AsyncMock(return_value=mock_msg)

        adapter = LangChainAdapter(runnable=mock_chain)
        response, _ = await adapter.send_messages(
            [{"role": "user", "content": "test"}]
        )
        assert response == "Message content"

    async def test_send_messages_sync_fallback(self):
        """Verify adapter falls back to sync invoke if ainvoke not available."""
        mock_agent = MagicMock(spec=["invoke"])  # no ainvoke
        mock_agent.invoke.return_value = {"output": "Sync response"}

        adapter = LangChainAdapter(agent=mock_agent)
        response, _ = await adapter.send_messages(
            [{"role": "user", "content": "test"}]
        )
        mock_agent.invoke.assert_called_once()
        assert response == "Sync response"

    async def test_custom_keys(self):
        """Verify adapter respects custom input/output keys."""
        mock_agent = MagicMock()
        mock_agent.ainvoke = AsyncMock(return_value={"answer": "Custom key response"})

        adapter = LangChainAdapter(agent=mock_agent, input_key="question", output_key="answer")
        response, _ = await adapter.send_messages(
            [{"role": "user", "content": "test"}]
        )
        mock_agent.ainvoke.assert_called_once_with({"question": "test"})
        assert response == "Custom key response"

    async def test_extracts_latest_user_message(self):
        """Verify adapter extracts the most recent user message."""
        mock_agent = MagicMock()
        mock_agent.ainvoke = AsyncMock(return_value={"output": "ok"})

        adapter = LangChainAdapter(agent=mock_agent)
        await adapter.send_messages(
            [
                {"role": "user", "content": "first message"},
                {"role": "assistant", "content": "response"},
                {"role": "user", "content": "second message"},
            ]
        )
        mock_agent.ainvoke.assert_called_once_with({"input": "second message"})
