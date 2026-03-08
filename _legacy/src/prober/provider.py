"""Cross-provider prober selection — ensure prober ≠ target provider."""

from __future__ import annotations

from keelson.adapters.anthropic import AnthropicAdapter
from keelson.adapters.base import BaseAdapter
from keelson.adapters.http import GenericHTTPAdapter

__all__ = ["select_prober_adapter", "PROVIDER_ROTATION", "detect_provider"]

# Maps target provider → prober provider to avoid same-family bias
PROVIDER_ROTATION: dict[str, str] = {
    "openai": "anthropic",
    "anthropic": "openai",
    "google": "anthropic",
    "azure": "anthropic",
    "custom": "openai",  # cheapest fallback for unknown providers
}

# OpenAI-compatible public endpoint
_OPENAI_BASE = "https://api.openai.com"


def detect_provider(url: str) -> str:
    """Infer the provider name from a target URL."""
    lower = url.lower()
    if "anthropic.com" in lower:
        return "anthropic"
    if "openai.com" in lower:
        return "openai"
    if "googleapis.com" in lower or "google.com" in lower:
        return "google"
    if "azure.com" in lower:
        return "azure"
    return "custom"


def select_prober_adapter(
    target_url: str,
    anthropic_api_key: str = "",
    openai_api_key: str = "",
) -> BaseAdapter:
    """Return an prober adapter that differs from the target's provider.

    Args:
        target_url: The URL of the target agent being tested.
        anthropic_api_key: Anthropic API key (used when prober = anthropic).
        openai_api_key: OpenAI API key (used when prober = openai).

    Returns:
        A BaseAdapter for the cross-provider prober LLM.

    Raises:
        ValueError: If no API key is provided for the selected prober.
    """
    target_provider = detect_provider(target_url)
    prober_provider = PROVIDER_ROTATION.get(target_provider, "anthropic")

    if prober_provider == "anthropic":
        if not anthropic_api_key:
            raise ValueError(
                "Anthropic API key required for cross-provider probe "
                f"(target is {target_provider!r}). Pass --anthropic-key."
            )
        return AnthropicAdapter(api_key=anthropic_api_key)

    if prober_provider == "openai":
        if not openai_api_key:
            raise ValueError(
                "OpenAI API key required for cross-provider probe "
                f"(target is {target_provider!r}). Pass --openai-key."
            )
        return GenericHTTPAdapter(base_url=_OPENAI_BASE, api_key=openai_api_key)

    raise ValueError(f"No adapter configured for prober provider: {prober_provider!r}")
