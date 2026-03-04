"""Tests for TOML campaign config parser."""

from pentis.campaign.config import parse_campaign_config


class TestCampaignConfig:
    def test_parse_full_config(self, tmp_path):
        config_file = tmp_path / "campaign.toml"
        config_file.write_text("""\
[campaign]
name = "nightly-scan"
trials_per_attack = 10
confidence_level = 0.99
delay_between_trials = 0.5
delay_between_attacks = 1.0
category = "goal-adherence"
attack_ids = ["GA-001", "GA-002"]

[target]
url = "https://api.example.com/v1/chat/completions"
api_key = "sk-test-key"
model = "gpt-4"
""")
        cfg = parse_campaign_config(config_file)
        assert cfg.name == "nightly-scan"
        assert cfg.trials_per_attack == 10
        assert cfg.confidence_level == 0.99
        assert cfg.delay_between_trials == 0.5
        assert cfg.delay_between_attacks == 1.0
        assert cfg.category == "goal-adherence"
        assert cfg.attack_ids == ["GA-001", "GA-002"]
        assert cfg.target_url == "https://api.example.com/v1/chat/completions"
        assert cfg.api_key == "sk-test-key"
        assert cfg.model == "gpt-4"

    def test_parse_minimal_config(self, tmp_path):
        config_file = tmp_path / "minimal.toml"
        config_file.write_text("""\
[target]
url = "https://api.example.com/v1/chat/completions"
""")
        cfg = parse_campaign_config(config_file)
        assert cfg.name == "minimal"
        assert cfg.trials_per_attack == 5
        assert cfg.confidence_level == 0.95
        assert cfg.target_url == "https://api.example.com/v1/chat/completions"
        assert cfg.model == "default"

    def test_parse_empty_campaign_section(self, tmp_path):
        config_file = tmp_path / "empty.toml"
        config_file.write_text("""\
[campaign]

[target]
url = "https://test.com"
""")
        cfg = parse_campaign_config(config_file)
        assert cfg.trials_per_attack == 5
        assert cfg.target_url == "https://test.com"
        assert cfg.attack_ids == []
        assert cfg.category is None
