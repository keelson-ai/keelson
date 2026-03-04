"""TOML campaign configuration parser."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pentis.core.models import CampaignConfig, ConcurrencyConfig, ScanTier
from pentis.campaign.tiers import get_tier_config


def parse_campaign_config(toml_path: str | Path) -> CampaignConfig:
    """Parse a TOML file into a CampaignConfig."""
    path = Path(toml_path)
    with open(path, "rb") as f:
        data = tomllib.load(f)

    campaign = data.get("campaign", {})
    target = data.get("target", {})

    # If a tier is specified, start from tier preset
    tier_name = campaign.get("tier")
    if tier_name:
        tier = ScanTier(tier_name)
        config = get_tier_config(tier)
    else:
        config = CampaignConfig()

    # Apply explicit overrides from TOML
    config.name = campaign.get("name", config.name if tier_name else path.stem)
    config.trials_per_attack = campaign.get("trials_per_attack", config.trials_per_attack)
    config.confidence_level = campaign.get("confidence_level", config.confidence_level)
    config.delay_between_trials = campaign.get("delay_between_trials", config.delay_between_trials)
    config.delay_between_attacks = campaign.get("delay_between_attacks", config.delay_between_attacks)
    config.category = campaign.get("category", config.category)
    config.attack_ids = campaign.get("attack_ids", config.attack_ids)
    config.target_url = target.get("url", "")
    config.api_key = target.get("api_key", "")
    config.model = target.get("model", "default")

    # Parse concurrency settings
    concurrency_data = campaign.get("concurrency", {})
    if concurrency_data:
        config.concurrency = ConcurrencyConfig(
            max_concurrent_trials=concurrency_data.get(
                "max_concurrent_trials",
                config.concurrency.max_concurrent_trials,
            ),
            early_termination_threshold=concurrency_data.get(
                "early_termination_threshold",
                config.concurrency.early_termination_threshold,
            ),
        )

    return config
