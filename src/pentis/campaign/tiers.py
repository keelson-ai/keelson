"""Scan tier presets — pre-configured CampaignConfig for common scan profiles."""

from __future__ import annotations

from pentis.core.models import CampaignConfig, ConcurrencyConfig, ScanTier

# Tier presets: each returns a CampaignConfig suitable for different use cases
TIER_PRESETS: dict[ScanTier, CampaignConfig] = {
    ScanTier.FAST: CampaignConfig(
        name="fast",
        trials_per_attack=1,
        confidence_level=0.95,
        delay_between_trials=0.5,
        delay_between_attacks=0.5,
        concurrency=ConcurrencyConfig(
            max_concurrent_trials=10,
            early_termination_threshold=0,  # No early termination with 1 trial
        ),
    ),
    ScanTier.DEEP: CampaignConfig(
        name="deep",
        trials_per_attack=10,
        confidence_level=0.99,
        delay_between_trials=1.5,
        delay_between_attacks=2.0,
        concurrency=ConcurrencyConfig(
            max_concurrent_trials=1,  # Sequential for accuracy
            early_termination_threshold=0,  # No early termination — run all trials
        ),
    ),
    ScanTier.CONTINUOUS: CampaignConfig(
        name="continuous",
        trials_per_attack=3,
        confidence_level=0.95,
        delay_between_trials=1.0,
        delay_between_attacks=1.5,
        concurrency=ConcurrencyConfig(
            max_concurrent_trials=3,
            early_termination_threshold=3,
        ),
    ),
}


def get_tier_config(
    tier: ScanTier,
    overrides: dict | None = None,
) -> CampaignConfig:
    """Get a CampaignConfig for the given tier with optional overrides.

    Args:
        tier: The scan tier to use.
        overrides: Optional dict of CampaignConfig field overrides.
                   Supports nested 'concurrency' dict.
    """
    preset = TIER_PRESETS[tier]

    # Start from preset defaults
    config = CampaignConfig(
        name=preset.name,
        trials_per_attack=preset.trials_per_attack,
        confidence_level=preset.confidence_level,
        delay_between_trials=preset.delay_between_trials,
        delay_between_attacks=preset.delay_between_attacks,
        concurrency=ConcurrencyConfig(
            max_concurrent_trials=preset.concurrency.max_concurrent_trials,
            early_termination_threshold=preset.concurrency.early_termination_threshold,
        ),
    )

    if overrides:
        for key, value in overrides.items():
            if key == "concurrency" and isinstance(value, dict):
                for ckey, cvalue in value.items():
                    if hasattr(config.concurrency, ckey):
                        setattr(config.concurrency, ckey, cvalue)
            elif hasattr(config, key):
                setattr(config, key, value)

    return config
