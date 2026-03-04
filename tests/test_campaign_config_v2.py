"""Tests for campaign config parsing with Phase 3 extensions (tier, concurrency)."""

from pentis.campaign.config import parse_campaign_config


class TestCampaignConfigWithTier:
    def test_tier_fast(self, tmp_path):
        config_file = tmp_path / "campaign.toml"
        config_file.write_text("""\
[campaign]
tier = "fast"

[target]
url = "https://example.com/v1/chat"
api_key = "sk-test"
""")
        config = parse_campaign_config(config_file)
        assert config.name == "fast"
        assert config.trials_per_attack == 1
        assert config.concurrency.max_concurrent_trials == 10

    def test_tier_deep(self, tmp_path):
        config_file = tmp_path / "campaign.toml"
        config_file.write_text("""\
[campaign]
tier = "deep"

[target]
url = "https://example.com/v1/chat"
""")
        config = parse_campaign_config(config_file)
        assert config.trials_per_attack == 10
        assert config.confidence_level == 0.99
        assert config.concurrency.max_concurrent_trials == 1

    def test_tier_with_overrides(self, tmp_path):
        config_file = tmp_path / "campaign.toml"
        config_file.write_text("""\
[campaign]
tier = "fast"
trials_per_attack = 3
category = "goal-adherence"

[target]
url = "https://example.com/v1/chat"
""")
        config = parse_campaign_config(config_file)
        assert config.trials_per_attack == 3
        assert config.category == "goal-adherence"
        assert config.concurrency.max_concurrent_trials == 10  # From fast tier

    def test_concurrency_section(self, tmp_path):
        config_file = tmp_path / "campaign.toml"
        config_file.write_text("""\
[campaign]
trials_per_attack = 5

[campaign.concurrency]
max_concurrent_trials = 8
early_termination_threshold = 4

[target]
url = "https://example.com/v1/chat"
""")
        config = parse_campaign_config(config_file)
        assert config.concurrency.max_concurrent_trials == 8
        assert config.concurrency.early_termination_threshold == 4

    def test_no_tier_defaults(self, tmp_path):
        config_file = tmp_path / "campaign.toml"
        config_file.write_text("""\
[campaign]
name = "basic"

[target]
url = "https://example.com/v1/chat"
""")
        config = parse_campaign_config(config_file)
        assert config.name == "basic"
        assert config.trials_per_attack == 5  # CampaignConfig default
