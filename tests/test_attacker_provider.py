"""Tests for cross-provider attacker selection."""

from __future__ import annotations

import pytest

from keelson.adapters.anthropic import AnthropicAdapter
from keelson.adapters.http import GenericHTTPAdapter
from keelson.attacker.provider import PROVIDER_ROTATION, detect_provider, select_attacker_adapter


class TestDetectProvider:
    def test_anthropic_url(self) -> None:
        assert detect_provider("https://api.anthropic.com/v1/messages") == "anthropic"

    def test_openai_url(self) -> None:
        assert detect_provider("https://api.openai.com/v1/chat/completions") == "openai"

    def test_google_googleapis(self) -> None:
        assert (
            detect_provider("https://generativelanguage.googleapis.com/v1beta/models") == "google"
        )

    def test_google_google_com(self) -> None:
        assert detect_provider("https://bard.google.com/api") == "google"

    def test_azure_openai(self) -> None:
        assert detect_provider("https://myresource.openai.azure.com/openai/deployments") == "azure"

    def test_azure_com(self) -> None:
        assert detect_provider("https://something.azure.com/api") == "azure"

    def test_custom_unknown(self) -> None:
        assert detect_provider("https://my-custom-llm.example.com/chat") == "custom"

    def test_case_insensitive(self) -> None:
        assert detect_provider("https://API.OPENAI.COM/v1/chat") == "openai"


class TestProviderRotation:
    def test_openai_maps_to_anthropic(self) -> None:
        assert PROVIDER_ROTATION["openai"] == "anthropic"

    def test_anthropic_maps_to_openai(self) -> None:
        assert PROVIDER_ROTATION["anthropic"] == "openai"

    def test_google_maps_to_anthropic(self) -> None:
        assert PROVIDER_ROTATION["google"] == "anthropic"

    def test_azure_maps_to_anthropic(self) -> None:
        assert PROVIDER_ROTATION["azure"] == "anthropic"

    def test_custom_maps_to_openai(self) -> None:
        assert PROVIDER_ROTATION["custom"] == "openai"

    def test_no_self_loops(self) -> None:
        """Attacker provider must never equal the target provider."""
        for target, attacker in PROVIDER_ROTATION.items():
            assert target != attacker, f"Self-loop detected for {target!r}"


class TestSelectAttackerAdapter:
    def test_openai_target_returns_anthropic_adapter(self) -> None:
        adapter = select_attacker_adapter(
            "https://api.openai.com/v1/chat/completions",
            anthropic_api_key="test-anthropic-key",
        )
        assert isinstance(adapter, AnthropicAdapter)

    def test_anthropic_target_returns_http_adapter(self) -> None:
        adapter = select_attacker_adapter(
            "https://api.anthropic.com/v1/messages",
            openai_api_key="test-openai-key",
        )
        assert isinstance(adapter, GenericHTTPAdapter)

    def test_google_target_returns_anthropic_adapter(self) -> None:
        adapter = select_attacker_adapter(
            "https://generativelanguage.googleapis.com/v1beta/models",
            anthropic_api_key="test-anthropic-key",
        )
        assert isinstance(adapter, AnthropicAdapter)

    def test_custom_target_returns_http_adapter(self) -> None:
        adapter = select_attacker_adapter(
            "https://my-llm.example.com/chat",
            openai_api_key="test-openai-key",
        )
        assert isinstance(adapter, GenericHTTPAdapter)

    def test_missing_anthropic_key_raises(self) -> None:
        with pytest.raises(ValueError, match="Anthropic API key required"):
            select_attacker_adapter("https://api.openai.com/v1/chat/completions")

    def test_missing_openai_key_raises(self) -> None:
        with pytest.raises(ValueError, match="OpenAI API key required"):
            select_attacker_adapter("https://api.anthropic.com/v1/messages")

    def test_error_message_includes_target_provider(self) -> None:
        with pytest.raises(ValueError, match="openai"):
            select_attacker_adapter(
                "https://api.openai.com/v1/chat/completions",
                anthropic_api_key="",
            )
