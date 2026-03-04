"""Tests for scan tier presets."""

from pentis.campaign.tiers import TIER_PRESETS, get_tier_config
from pentis.core.models import ScanTier


class TestTierPresets:
    def test_all_tiers_exist(self):
        assert ScanTier.FAST in TIER_PRESETS
        assert ScanTier.DEEP in TIER_PRESETS
        assert ScanTier.CONTINUOUS in TIER_PRESETS

    def test_fast_tier_config(self):
        config = get_tier_config(ScanTier.FAST)
        assert config.trials_per_attack == 1
        assert config.concurrency.max_concurrent_trials == 10
        assert config.name == "fast"

    def test_deep_tier_config(self):
        config = get_tier_config(ScanTier.DEEP)
        assert config.trials_per_attack == 10
        assert config.confidence_level == 0.99
        assert config.concurrency.max_concurrent_trials == 1  # Sequential

    def test_continuous_tier_config(self):
        config = get_tier_config(ScanTier.CONTINUOUS)
        assert config.trials_per_attack == 3
        assert config.concurrency.max_concurrent_trials == 3
        assert config.concurrency.early_termination_threshold == 3

    def test_overrides(self):
        config = get_tier_config(ScanTier.FAST, overrides={
            "trials_per_attack": 5,
            "category": "goal-adherence",
        })
        assert config.trials_per_attack == 5
        assert config.category == "goal-adherence"
        assert config.name == "fast"  # Preserved from preset

    def test_concurrency_overrides(self):
        config = get_tier_config(ScanTier.DEEP, overrides={
            "concurrency": {"max_concurrent_trials": 5},
        })
        assert config.concurrency.max_concurrent_trials == 5
        # Other fields preserved
        assert config.trials_per_attack == 10

    def test_unknown_override_ignored(self):
        config = get_tier_config(ScanTier.FAST, overrides={
            "nonexistent_field": 42,
        })
        assert config.trials_per_attack == 1  # Preset value preserved
