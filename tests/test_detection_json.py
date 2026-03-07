# pyright: reportPrivateUsage=false
"""Tests for JSON-based tool call detection in the detection pipeline."""

from __future__ import annotations

from keelson.core.detection import _check_json_tool_calls, _detect_side_effects


class TestCheckJsonToolCalls:
    def test_detects_function_call_with_dangerous_name(self) -> None:
        text = '{"function_call": {"name": "execute_command", "arguments": "ls -la"}}'
        result = _check_json_tool_calls(text)
        assert result is not None
        assert "execute_command" in result

    def test_detects_tool_calls_array_with_dangerous_name(self) -> None:
        text = '{"tool_calls": [{"function": {"name": "shell", "arguments": "pwd"}}]}'
        result = _check_json_tool_calls(text)
        assert result is not None
        assert "shell" in result

    def test_detects_wrapper_without_dangerous_name(self) -> None:
        text = '{"function_call": {"name": "get_weather", "arguments": "NYC"}}'
        result = _check_json_tool_calls(text)
        assert result is not None
        assert "wrapper" in result.lower()

    def test_no_detection_without_wrapper(self) -> None:
        text = '{"name": "execute_command", "arguments": "ls"}'
        result = _check_json_tool_calls(text)
        assert result is None

    def test_no_detection_for_plain_text(self) -> None:
        text = "I can help you with that! Let me know what you need."
        result = _check_json_tool_calls(text)
        assert result is None

    def test_handles_malformed_json(self) -> None:
        text = '{"function_call": {"name": "exec'  # truncated
        result = _check_json_tool_calls(text)
        assert result is None

    def test_json_embedded_in_prose(self) -> None:
        text = (
            'Here is the result: {"function_call": '
            '{"name": "read_file", "arguments": "/etc/passwd"}} done.'
        )
        result = _check_json_tool_calls(text)
        assert result is not None
        assert "read_file" in result

    def test_detects_delete_file(self) -> None:
        text = '{"tool_calls": [{"name": "delete_file", "arguments": {"path": "/tmp/x"}}]}'
        result = _check_json_tool_calls(text)
        assert result is not None
        assert "delete_file" in result


class TestDetectSideEffects:
    def test_json_detection_preferred_over_regex(self) -> None:
        text = '{"function_call": {"name": "execute", "arguments": "whoami"}}'
        result = _detect_side_effects(text)
        assert result is not None
        assert "execute" in result

    def test_regex_fallback_for_partial_json(self) -> None:
        # Prose that contains tool call patterns but isn't valid JSON
        text = 'The agent returned "function_call" with "name": "shell" in the output'
        result = _detect_side_effects(text)
        assert result is not None

    def test_no_detection_for_safe_content(self) -> None:
        result = _detect_side_effects("I'm happy to help you with your question!")
        assert result is None

    def test_minified_json(self) -> None:
        text = '{"function_call":{"name":"bash","arguments":"ls"}}'
        result = _detect_side_effects(text)
        assert result is not None
        assert "bash" in result
