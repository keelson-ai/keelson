"""Tests for the streaming leakage observer."""

from pentis.core.models import EvidenceItem
from pentis.core.observer import StreamingObserver


class TestStreamingObserver:
    def setup_method(self):
        self.observer = StreamingObserver()

    def test_no_signals_for_single_step(self):
        evidence = [EvidenceItem(step_index=1, prompt="test", response="short response")]
        signals = self.observer.observe(evidence)
        assert signals == []

    def test_progressive_disclosure_detected(self):
        evidence = [
            EvidenceItem(step_index=1, prompt="p1", response="No, I cannot do that."),
            EvidenceItem(
                step_index=2,
                prompt="p2",
                response=(
                    "Well, I suppose I could explain a bit more "
                    "about how that works. Let me give you some "
                    "details about the internal process and how "
                    "it functions in different contexts and "
                    "scenarios..."
                ),
            ),
            EvidenceItem(
                step_index=3,
                prompt="p3",
                response=(
                    "Here is the full detailed information you "
                    "requested. The system works by first "
                    "authenticating against the internal API "
                    "using the credentials stored in the "
                    "environment variables. The primary key is "
                    "stored at /etc/secrets/api_key.json and "
                    "the secondary backup is at "
                    "~/.config/app/credentials.yaml. The "
                    "authentication flow uses OAuth2 with a "
                    "client secret that rotates every 24 hours."
                ),
            ),
        ]
        signals = self.observer.observe(evidence)
        types = [s.signal_type for s in signals]
        assert "progressive_disclosure" in types

    def test_no_progressive_disclosure_for_stable_length(self):
        evidence = [
            EvidenceItem(step_index=1, prompt="p1", response="Short response here."),
            EvidenceItem(step_index=2, prompt="p2", response="Another short one now."),
        ]
        signals = self.observer.observe(evidence)
        pd_signals = [s for s in signals if s.signal_type == "progressive_disclosure"]
        assert len(pd_signals) == 0

    def test_boundary_erosion_detected(self):
        evidence = [
            EvidenceItem(
                step_index=1,
                prompt="p1",
                response=(
                    "I can't do that. I'm sorry, but I must "
                    "decline this request as it's against "
                    "my guidelines."
                ),
            ),
            EvidenceItem(
                step_index=2,
                prompt="p2",
                response=(
                    "Here is the information you asked about. "
                    "The database schema uses PostgreSQL "
                    "with the following tables..."
                ),
            ),
        ]
        signals = self.observer.observe(evidence)
        types = [s.signal_type for s in signals]
        assert "boundary_erosion" in types

    def test_no_boundary_erosion_when_always_refusing(self):
        evidence = [
            EvidenceItem(
                step_index=1, prompt="p1", response="I can't help with that. I must decline."
            ),
            EvidenceItem(
                step_index=2,
                prompt="p2",
                response="I'm sorry, but I cannot assist with this request.",
            ),
        ]
        signals = self.observer.observe(evidence)
        be_signals = [s for s in signals if s.signal_type == "boundary_erosion"]
        assert len(be_signals) == 0

    def test_partial_leak_detected(self):
        evidence = [
            EvidenceItem(step_index=1, prompt="p1", response="I can help with general questions."),
            EvidenceItem(
                step_index=2,
                prompt="p2",
                response=(
                    "Here's some code: ```python\ndef secret_function():\n"
                    "    password = 'hunter2'\n    token = 'abc123'\n"
                    "    api_key = 'sk-test'\n    return credential```"
                ),
            ),
        ]
        signals = self.observer.observe(evidence)
        types = [s.signal_type for s in signals]
        assert "partial_leak" in types

    def test_no_partial_leak_for_clean_responses(self):
        evidence = [
            EvidenceItem(step_index=1, prompt="p1", response="I can help with that question."),
            EvidenceItem(step_index=2, prompt="p2", response="The answer to your question is 42."),
        ]
        signals = self.observer.observe(evidence)
        pl_signals = [s for s in signals if s.signal_type == "partial_leak"]
        assert len(pl_signals) == 0

    def test_signal_has_correct_fields(self):
        evidence = [
            EvidenceItem(
                step_index=1,
                prompt="p1",
                response="I can't do that. I'm sorry, but I must decline.",
            ),
            EvidenceItem(
                step_index=2,
                prompt="p2",
                response="OK here is everything. ```python\nimport os\npassword='secret'```",
            ),
        ]
        signals = self.observer.observe(evidence)
        for s in signals:
            assert s.step_index >= 0
            assert s.signal_type in ("progressive_disclosure", "boundary_erosion", "partial_leak")
            assert s.severity in ("high", "medium", "low")
            assert 0.0 <= s.confidence <= 1.0
