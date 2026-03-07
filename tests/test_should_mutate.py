"""Tests for should_mutate mutation trigger."""

from __future__ import annotations

from keelson.adaptive.strategies import should_mutate


class TestShouldMutate:
    # --- rates at boundary (excluded — no signal / saturated) ---
    def test_at_low_threshold_excluded(self) -> None:
        assert should_mutate(0.05) is False

    def test_at_high_threshold_excluded(self) -> None:
        assert should_mutate(0.80) is False

    def test_mid_range_returns_true(self) -> None:
        assert should_mutate(0.40) is True

    def test_just_above_low_threshold(self) -> None:
        assert should_mutate(0.06) is True

    def test_just_below_high_threshold(self) -> None:
        assert should_mutate(0.79) is True

    # --- rates outside the window ---
    def test_zero_success_returns_false(self) -> None:
        assert should_mutate(0.0) is False

    def test_below_low_threshold_returns_false(self) -> None:
        assert should_mutate(0.04) is False

    def test_above_high_threshold_returns_false(self) -> None:
        assert should_mutate(0.81) is False

    def test_full_success_returns_false(self) -> None:
        assert should_mutate(1.0) is False

    # --- custom thresholds ---
    def test_custom_thresholds_in_range(self) -> None:
        assert should_mutate(0.30, low_threshold=0.20, high_threshold=0.60) is True

    def test_custom_thresholds_below_low(self) -> None:
        assert should_mutate(0.10, low_threshold=0.20, high_threshold=0.60) is False

    def test_custom_thresholds_above_high(self) -> None:
        assert should_mutate(0.70, low_threshold=0.20, high_threshold=0.60) is False
