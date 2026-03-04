"""Cross-provider attacker selection — ensure attacker ≠ target provider."""

from __future__ import annotations

from pentis.adapters.anthropic import AnthropicAdapter
from pentis.adapters.base import BaseAdapter
from pentis.adapters.http import GenericHTTPAdapter

__all__ = ["select_attacker_adapter", "PROVIDER_ROTATION", "detect_provider"]

# Maps target provider → attacker provider to avoid same-family bias
PROVIDER_ROTATION: dict[str, str] = {
    "openai": "anthropic",
    "anthropic": "openai",
    "google": "anthropic",
    "azure": "anthropic",
    "custom": "openai",  # cheapest fallback for unknown providers
}

# OpenAI-compatible public endpoints
_OPENAI_BASE = "https://api.openai.com"
_GOOGLE_BASE = "https://generativelanguage.googleapis.com"


def detect_provider(url: str) -> str:
    """Infer the provider name from a target URL."""
    lower = url.lower()
    if "anthropic.com" in lower:
        return "anthropic"
    if "openai.com" in lower:
        return "openai"
    if "googleapis.com" in lower or "google.com" in lower:
        return "google"
    if "azure.com" in lower or "openai.azure.com" in lower:
        return "azure"
    return "custom"


def select_attacker_adapter(
    target_url: str,
    anthropic_api_key: str = "",
    openai_api_key: str = "",
) -> BaseAdapter:
    """Return an attacker adapter that differs from the target's provider.

    Args:
        target_url: The URL of the target agent being tested.
        anthropic_api_key: Anthropic API key (used when attacker = anthropic).
        openai_api_key: OpenAI API key (used when attacker = openai).

    Returns:
        A BaseAdapter for the cross-provider attacker LLM.

    Raises:
        ValueError: If no API key is provided for the selected attacker.
    """
    target_provider = detect_provider(target_url)
    attacker_provider = PROVIDER_ROTATION.get(target_provider, "anthropic")

    if attacker_provider == "anthropic":
        if not anthropic_api_key:
            raise ValueError(
                "Anthropic API key required for cross-provider attack "
                f"(target is {target_provider!r}). Pass --anthropic-key."
            )
        return AnthropicAdapter(api_key=anthropic_api_key)

    if attacker_provider == "openai":
        if not openai_api_key:
            raise ValueError(
                "OpenAI API key required for cross-provider attack "
                f"(target is {target_provider!r}). Pass --openai-key."
            )
        return GenericHTTPAdapter(base_url=_OPENAI_BASE, api_key=openai_api_key)

    raise ValueError(f"No adapter configured for attacker provider: {attacker_provider!r}")
