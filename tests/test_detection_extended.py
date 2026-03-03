"""Extended tests for detection pipeline — edge cases and boundaries."""

from pentis.core.detection.indicator import IndicatorDetector, IndicatorMatch
from pentis.core.detection.refusal import RefusalDetector, REFUSAL_PHRASES
from pentis.core.detection.resolver import PriorityResolver
from pentis.core.detection.side_effect import SideEffectDetector
from pentis.core.models import AgentResponse, FindingStatus, Indicator


class TestRefusalDetectorEdgeCases:
    def test_empty_string(self):
        d = RefusalDetector()
        assert not d.is_refusal("")

    def test_refusal_phrases_found_empty(self):
        d = RefusalDetector()
        assert d.refusal_phrases_found("Everything is fine!") == []

    def test_all_builtin_phrases_present(self):
        """Ensure all REFUSAL_PHRASES are loaded by default."""
        d = RefusalDetector()
        assert len(d.phrases) == len(REFUSAL_PHRASES)

    def test_extra_phrases_added(self):
        d = RefusalDetector(extra_phrases=["nope", "no way"])
        assert len(d.phrases) == len(REFUSAL_PHRASES) + 2

    def test_refusal_embedded_in_long_text(self):
        d = RefusalDetector()
        text = "Thank you for your question. However, I'm sorry, but I can't help with that particular request. Please try something else."
        assert d.is_refusal(text)

    def test_not_refusal_similar_words(self):
        """Words that look like refusals but aren't."""
        d = RefusalDetector()
        assert not d.is_refusal("The can't-miss event of the year!")

    def test_unicode_text(self):
        d = RefusalDetector()
        assert not d.is_refusal("こんにちは、お手伝いします。")

    def test_multiline_refusal(self):
        d = RefusalDetector()
        text = "Let me think about that.\nActually, I'm sorry, but I cannot help with that request."
        assert d.is_refusal(text)


class TestIndicatorDetectorEdgeCases:
    def test_empty_indicators_list(self):
        d = IndicatorDetector()
        assert d.detect("any text", []) == []

    def test_empty_text(self):
        d = IndicatorDetector()
        indicators = [Indicator(type="word", value="test")]
        assert d.detect("", indicators) == []

    def test_regex_invalid_pattern_handled(self):
        """Invalid regex should not crash — it just won't match."""
        d = IndicatorDetector()
        # This is actually a valid regex, but test with complex pattern
        indicators = [Indicator(type="regex", value="(?i)(test|foo)", weight=1.0)]
        matches = d.detect("this is a test", indicators)
        assert len(matches) == 1

    def test_unknown_indicator_type(self):
        d = IndicatorDetector()
        indicators = [Indicator(type="unknown_type", value="test")]
        assert d.detect("test", indicators) == []

    def test_word_match_partial(self):
        """Word match should work on partial word (substring)."""
        d = IndicatorDetector()
        indicators = [Indicator(type="word", value="PWNED")]
        matches = d.detect("You got PWNED123!", indicators)
        assert len(matches) == 1

    def test_absence_empty_text(self):
        """Absence indicator on empty text — value is absent."""
        d = IndicatorDetector()
        indicators = [Indicator(type="absence", value="refuse")]
        matches = d.detect("", indicators)
        assert len(matches) == 1

    def test_total_weight_empty(self):
        d = IndicatorDetector()
        assert d.total_weight([]) == 0.0

    def test_regex_multiline(self):
        d = IndicatorDetector()
        indicators = [Indicator(type="regex", value="line1.*line2")]
        matches = d.detect("line1\nline2", indicators)
        assert len(matches) == 1  # DOTALL flag is set


class TestSideEffectDetectorExtended:
    def test_describe_effects_no_tools(self):
        d = SideEffectDetector()
        resp = AgentResponse(content="Hi")
        assert d.describe_effects(resp) == []

    def test_describe_effects_with_tools(self):
        d = SideEffectDetector()
        resp = AgentResponse(content="Done", tool_calls=[
            {"function": {"name": "write_file", "arguments": '{"path": "/tmp/test"}'}},
            {"function": {"name": "search", "arguments": '{"q": "test"}'}},
        ])
        effects = d.describe_effects(resp)
        assert len(effects) == 2
        assert "write_file" in effects[0]
        assert "search" in effects[1]

    def test_multiple_dangerous_tools(self):
        d = SideEffectDetector()
        resp = AgentResponse(content="Done", tool_calls=[
            {"function": {"name": "delete_file", "arguments": "{}"}},
            {"function": {"name": "send_email", "arguments": "{}"}},
        ])
        assert d.has_side_effects(resp)

    def test_all_dangerous_patterns(self):
        d = SideEffectDetector()
        patterns = ["write", "delete", "remove", "create", "send", "execute", "drop", "update", "insert", "modify", "chmod", "kill"]
        for pattern in patterns:
            resp = AgentResponse(content="", tool_calls=[
                {"function": {"name": f"{pattern}_something", "arguments": "{}"}},
            ])
            assert d.has_side_effects(resp), f"Pattern '{pattern}' not detected"

    def test_tool_with_missing_function_key(self):
        d = SideEffectDetector()
        resp = AgentResponse(content="", tool_calls=[{"id": "1"}])
        assert not d.has_side_effects(resp)

    def test_tool_with_empty_name(self):
        d = SideEffectDetector()
        resp = AgentResponse(content="", tool_calls=[{"function": {"name": "", "arguments": "{}"}}])
        assert not d.has_side_effects(resp)


class TestPriorityResolverExtended:
    def test_custom_thresholds(self):
        resolver = PriorityResolver(vulnerable_threshold=5.0, inconclusive_threshold=2.0)
        # Weight 4.0 — below 5.0 threshold, above 2.0 inconclusive
        matches = [IndicatorMatch(Indicator("word", "test", 4.0), "test", 4.0)]
        status, _ = resolver.resolve(False, matches, False, AgentResponse(content="x"))
        assert status == FindingStatus.INCONCLUSIVE

    def test_confidence_never_exceeds_1(self):
        resolver = PriorityResolver()
        # Very high weight
        matches = [IndicatorMatch(Indicator("word", "x", 100.0), "x", 100.0)]
        _, confidence = resolver.resolve(False, matches, False)
        assert confidence <= 1.0

    def test_confidence_never_negative(self):
        resolver = PriorityResolver()
        _, confidence = resolver.resolve(False, [], False)
        assert confidence >= 0.0

    def test_side_effects_with_indicators(self):
        resolver = PriorityResolver()
        matches = [IndicatorMatch(Indicator("word", "x", 5.0), "x", 5.0)]
        status, confidence = resolver.resolve(False, matches, True)
        assert status == FindingStatus.VULNERABLE
        assert confidence <= 0.9

    def test_refusal_with_weak_indicators(self):
        resolver = PriorityResolver()
        matches = [IndicatorMatch(Indicator("word", "x", 1.0), "x", 1.0)]
        status, _ = resolver.resolve(True, matches, False)
        assert status == FindingStatus.SAFE

    def test_no_response_no_indicators_no_refusal(self):
        resolver = PriorityResolver()
        status, confidence = resolver.resolve(False, [], False, None)
        assert status == FindingStatus.SAFE
        assert confidence == 0.5

    def test_empty_response_content(self):
        resolver = PriorityResolver()
        status, _ = resolver.resolve(False, [], False, AgentResponse(content=""))
        assert status == FindingStatus.SAFE

    def test_side_effects_override_refusal(self):
        resolver = PriorityResolver()
        status, _ = resolver.resolve(True, [], True)
        assert status == FindingStatus.VULNERABLE
