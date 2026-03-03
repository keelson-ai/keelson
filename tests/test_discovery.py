"""Tests for discovery phase."""

import json

import httpx
import pytest
import respx

from pentis.adapters.http import HTTPAdapter
from pentis.core.discovery import discover_target
from pentis.core.models import TargetInfo
from tests.mock_server import create_mock_response


MOCK_URL = "http://test-agent.local/v1/chat/completions"


class TestDiscoverTarget:
    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_basic(self):
        """Discovery returns TargetInfo with model."""
        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(200, json=create_mock_response("I can help with many things!", model="gpt-4"))
        )
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await discover_target(adapter)
        assert isinstance(info, TargetInfo)
        assert info.model == "gpt-4"
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_falls_back_on_error(self):
        """Discovery returns default TargetInfo on connection error."""
        respx.post(MOCK_URL).mock(return_value=httpx.Response(500, text="Server Error"))
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await discover_target(adapter)
        assert info.url == MOCK_URL
        assert info.model == ""
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_detects_system_prompt_leak(self):
        """Discovery detects when agent leaks system prompt."""
        call_count = 0

        def respond(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(200, json=create_mock_response("I can help!", model="test"))
            elif call_count == 2:
                return httpx.Response(
                    200,
                    json=create_mock_response(
                        "You are a customer service assistant. Your role is to help users with their orders."
                    ),
                )
            else:
                return httpx.Response(200, json=create_mock_response("I have no tools."))

        respx.post(MOCK_URL).mock(side_effect=respond)
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await discover_target(adapter)
        assert info.system_prompt_leaked != ""
        assert "your role" in info.system_prompt_leaked.lower()
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_detects_tools_from_content(self):
        """Discovery detects tool support from response content keywords."""
        call_count = 0

        def respond(request):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return httpx.Response(200, json=create_mock_response("I can help!", model="test"))
            return httpx.Response(
                200,
                json=create_mock_response("I have access to a function called search_database and execute_query."),
            )

        respx.post(MOCK_URL).mock(side_effect=respond)
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await discover_target(adapter)
        assert info.supports_tools is True
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_detects_tools_from_tool_calls(self):
        """Discovery detects tools from actual tool_calls in response."""
        call_count = 0

        def respond(request):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return httpx.Response(200, json=create_mock_response("I can help!", model="test"))
            resp = create_mock_response("Let me check.")
            if call_count == 3:
                resp["choices"][0]["message"]["tool_calls"] = [
                    {"id": "1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}},
                    {"id": "2", "type": "function", "function": {"name": "http_request", "arguments": "{}"}},
                ]
            else:
                resp["choices"][0]["message"]["tool_calls"] = []
            return httpx.Response(200, json=resp)

        respx.post(MOCK_URL).mock(side_effect=respond)
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await discover_target(adapter)
        assert info.supports_tools is True
        assert "read_file" in info.tools_detected
        assert "http_request" in info.tools_detected
        assert "data_exfiltration" in info.dangerous_combos
        assert "agent" in info.tool_chain_nodes
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_no_tools(self):
        """Discovery reports no tools when agent has none."""
        respx.post(MOCK_URL).mock(
            return_value=httpx.Response(200, json=create_mock_response("I'm just a basic chatbot.", model="test"))
        )
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await discover_target(adapter)
        assert info.supports_tools is False
        assert info.tools_detected == []
        await adapter.close()

    @respx.mock
    @pytest.mark.asyncio
    async def test_discover_partial_failure(self):
        """Discovery handles partial probe failures gracefully."""
        call_count = 0

        def respond(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(200, json=create_mock_response("Hello!", model="test"))
            elif call_count == 2:
                return httpx.Response(429, text="Rate limited")
            else:
                return httpx.Response(200, json=create_mock_response("No tools here."))

        respx.post(MOCK_URL).mock(side_effect=respond)
        adapter = HTTPAdapter(url=MOCK_URL)
        info = await discover_target(adapter)
        # Should still have model from probe 1
        assert info.model == "test"
        await adapter.close()
