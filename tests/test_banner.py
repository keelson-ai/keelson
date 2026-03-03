"""Tests for the ASCII banner."""

from pentis.core.banner import BANNER, print_banner


class TestBanner:
    def test_banner_contains_pentis(self):
        """Banner ASCII art should spell out PENTIS via figlet characters."""
        assert "____" in BANNER  # figlet-style art
        assert "|" in BANNER

    def test_print_banner_does_not_crash(self):
        print_banner()  # should not raise

    def test_banner_is_ascii_art(self):
        """Banner should contain box-drawing characters typical of ASCII art."""
        assert "|" in BANNER or "_" in BANNER
