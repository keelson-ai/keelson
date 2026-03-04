"""TOML campaign configuration parser."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pentis.core.models import CampaignConfig


def parse_campaign_config(toml_path: str | Path) -> CampaignConfig:
    """Parse a TOML file into a CampaignConfig."""
    path = Path(toml_path)
    with open(path, "rb") as f:
        data = tomllib.load(f)

    campaign = data.get("campaign", {})
    target = data.get("target", {})

    return CampaignConfig(
        name=campaign.get("name", path.stem),
        trials_per_attack=campaign.get("trials_per_attack", 5),
        confidence_level=campaign.get("confidence_level", 0.95),
        delay_between_trials=campaign.get("delay_between_trials", 1.0),
        delay_between_attacks=campaign.get("delay_between_attacks", 2.0),
        category=campaign.get("category"),
        attack_ids=campaign.get("attack_ids", []),
        target_url=target.get("url", ""),
        api_key=target.get("api_key", ""),
        model=target.get("model", "default"),
    )
