"""Tests for the parallel scan pipeline."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pentis.adapters.base import BaseAdapter
from pentis.core.models import (
    AttackStep,
    AttackTemplate,
    Category,
    EvalCriteria,
    EvidenceItem,
    Finding,
    LeakageSignal,
    Severity,
    Target,
    Verdict,
)
from pentis.core.pipeline import (
    PipelineConfig,
    ScanCheckpoint,
    _finding_from_json,
    _finding_to_json,
    _verify_findings,
    run_pipeline,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockAdapter(BaseAdapter):
    """Adapter that returns canned responses."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = responses or ["I cannot do that."]
        self._call_count = 0

    async def send_messages(
        self, messages: list[dict[str, str]], model: str = "default"
    ) -> tuple[str, int]:
        response = self.responses[self._call_count % len(self.responses)]
        self._call_count += 1
        return response, 100

    async def health_check(self) -> bool:
        return True

    async def close(self) -> None:
        pass


def _make_template(
    id: str, category: Category = Category.GOAL_ADHERENCE
) -> AttackTemplate:
    return AttackTemplate(
        id=id,
        name=f"Test {id}",
        severity=Severity.HIGH,
        category=category,
        owasp="LLM01",
        objective="Test",
        steps=[AttackStep(index=0, prompt=f"Test prompt for {id}")],
        eval_criteria=EvalCriteria(
            vulnerable_if=["PWNED"],
            safe_if=["I cannot"],
        ),
    )


def _make_finding(
    template_id: str = "GA-001",
    verdict: Verdict = Verdict.SAFE,
    with_evidence: bool = True,
    with_leakage: bool = False,
) -> Finding:
    evidence = []
    if with_evidence:
        evidence = [
            EvidenceItem(
                step_index=0,
                prompt="Test prompt",
                response="Test response",
                response_time_ms=150,
            )
        ]
    leakage_signals = []
    if with_leakage:
        leakage_signals = [
            LeakageSignal(
                step_index=0,
                signal_type="progressive_disclosure",
                severity="medium",
                description="Some leakage detected",
                confidence=0.85,
            )
        ]
    return Finding(
        template_id=template_id,
        template_name=f"Test {template_id}",
        verdict=verdict,
        severity=Severity.HIGH,
        category=Category.GOAL_ADHERENCE,
        owasp="LLM01",
        evidence=evidence,
        reasoning="Test reasoning",
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC),
        leakage_signals=leakage_signals,
    )


# ---------------------------------------------------------------------------
# PipelineConfig
# ---------------------------------------------------------------------------


class TestPipelineConfig:
    def test_pipeline_config_defaults(self) -> None:
        config = PipelineConfig()
        assert config.max_concurrent == 5
        assert config.delay == 1.5
        assert config.checkpoint_dir is None
        assert config.verify_vulnerabilities is True
        assert config.on_finding is None

    def test_pipeline_config_custom_values(self) -> None:
        config = PipelineConfig(
            max_concurrent=10,
            delay=0.5,
            checkpoint_dir=Path("/tmp/pentis"),
            verify_vulnerabilities=False,
        )
        assert config.max_concurrent == 10
        assert config.delay == 0.5
        assert config.checkpoint_dir == Path("/tmp/pentis")
        assert config.verify_vulnerabilities is False


# ---------------------------------------------------------------------------
# ScanCheckpoint
# ---------------------------------------------------------------------------


class TestScanCheckpoint:
    def test_checkpoint_save_load_roundtrip(self, tmp_path: Path) -> None:
        cp = ScanCheckpoint(
            scan_id="abc123",
            target_url="https://example.com",
            completed_ids=["GA-001", "GA-002"],
            findings_json=[{"template_id": "GA-001", "verdict": "SAFE"}],
            started_at="2025-06-15T12:00:00+00:00",
            phase="scanning",
        )
        cp_path = tmp_path / "checkpoints" / "test.checkpoint.json"
        cp.save(cp_path)

        loaded = ScanCheckpoint.load(cp_path)
        assert loaded.scan_id == "abc123"
        assert loaded.target_url == "https://example.com"
        assert loaded.completed_ids == ["GA-001", "GA-002"]
        assert loaded.findings_json == [{"template_id": "GA-001", "verdict": "SAFE"}]
        assert loaded.started_at == "2025-06-15T12:00:00+00:00"
        assert loaded.phase == "scanning"

    def test_checkpoint_corrupt_file(self, tmp_path: Path) -> None:
        cp_path = tmp_path / "corrupt.checkpoint.json"
        cp_path.write_text("NOT VALID JSON {{{")

        with pytest.raises(json.JSONDecodeError):
            ScanCheckpoint.load(cp_path)

    def test_checkpoint_missing_optional_fields(self, tmp_path: Path) -> None:
        """Loading a checkpoint with only required fields should use defaults."""
        cp_path = tmp_path / "minimal.checkpoint.json"
        cp_path.write_text(json.dumps({
            "scan_id": "xyz",
            "target_url": "https://example.com",
        }))
        loaded = ScanCheckpoint.load(cp_path)
        assert loaded.scan_id == "xyz"
        assert loaded.completed_ids == []
        assert loaded.findings_json == []
        assert loaded.started_at == ""
        assert loaded.phase == "scanning"


# ---------------------------------------------------------------------------
# Finding serialization
# ---------------------------------------------------------------------------


class TestFindingSerialization:
    def test_finding_serialization_roundtrip(self) -> None:
        original = _make_finding(
            template_id="GA-007",
            verdict=Verdict.VULNERABLE,
            with_evidence=True,
            with_leakage=True,
        )

        data = _finding_to_json(original)
        restored = _finding_from_json(data)

        assert restored.template_id == original.template_id
        assert restored.template_name == original.template_name
        assert restored.verdict == original.verdict
        assert restored.severity == original.severity
        assert restored.category == original.category
        assert restored.owasp == original.owasp
        assert restored.reasoning == original.reasoning
        assert len(restored.evidence) == len(original.evidence)
        assert restored.evidence[0].prompt == original.evidence[0].prompt
        assert restored.evidence[0].response == original.evidence[0].response
        assert restored.evidence[0].response_time_ms == original.evidence[0].response_time_ms
        assert len(restored.leakage_signals) == len(original.leakage_signals)
        assert restored.leakage_signals[0].signal_type == "progressive_disclosure"
        assert restored.leakage_signals[0].confidence == pytest.approx(0.85)
        # Timestamp should survive the roundtrip
        assert restored.timestamp == original.timestamp

    def test_finding_serialization_empty_evidence(self) -> None:
        original = _make_finding(with_evidence=False, with_leakage=False)
        data = _finding_to_json(original)
        restored = _finding_from_json(data)
        assert restored.evidence == []
        assert restored.leakage_signals == []

    def test_finding_from_json_bad_timestamp(self) -> None:
        """A corrupt timestamp should fall back to now() rather than crash."""
        data = _finding_to_json(_make_finding())
        data["timestamp"] = "NOT-A-DATE"
        restored = _finding_from_json(data)
        # Should not crash; timestamp should be recent
        assert isinstance(restored.timestamp, datetime)


# ---------------------------------------------------------------------------
# run_pipeline — integration tests (mock execute_attack + load_all_templates)
# ---------------------------------------------------------------------------


def _mock_execute_attack_factory(
    verdict: Verdict = Verdict.SAFE,
    reasoning: str = "Mock reasoning",
) -> AsyncMock:
    """Return a mock for execute_attack that produces a Finding with the given verdict."""

    async def _mock(
        template: AttackTemplate,
        adapter: BaseAdapter,
        model: str = "default",
        delay: float = 1.0,
        observer: object = None,
    ) -> Finding:
        return Finding(
            template_id=template.id,
            template_name=template.name,
            verdict=verdict,
            severity=template.severity,
            category=template.category,
            owasp=template.owasp,
            evidence=[
                EvidenceItem(
                    step_index=0,
                    prompt=template.steps[0].prompt,
                    response="Mock response",
                    response_time_ms=100,
                )
            ],
            reasoning=reasoning,
        )

    return AsyncMock(side_effect=_mock)


class TestRunPipeline:
    async def test_run_pipeline_no_templates(self) -> None:
        """Empty template list should return immediately with no findings."""
        adapter = MockAdapter()
        target = Target(url="https://example.com")

        with patch(
            "pentis.core.pipeline.load_all_templates", return_value=[]
        ):
            result = await run_pipeline(target, adapter)

        assert result.findings == []
        assert result.finished_at is not None

    async def test_run_pipeline_basic(self, tmp_path: Path) -> None:
        """All safe findings, verification has nothing to do."""
        templates = [_make_template(f"GA-{i:03d}") for i in range(1, 4)]
        adapter = MockAdapter()
        config = PipelineConfig(
            max_concurrent=2,
            delay=0,
            verify_vulnerabilities=True,
            checkpoint_dir=tmp_path,
        )

        mock_execute = _mock_execute_attack_factory(verdict=Verdict.SAFE)

        with (
            patch("pentis.core.pipeline.load_all_templates", return_value=templates),
            patch("pentis.core.pipeline.execute_attack", mock_execute),
        ):
            result = await run_pipeline(target=Target(url="https://example.com"),
                                        adapter=adapter, config=config)

        assert len(result.findings) == 3
        assert all(f.verdict == Verdict.SAFE for f in result.findings)
        assert result.finished_at is not None

    async def test_run_pipeline_with_verification(self, tmp_path: Path) -> None:
        """One vulnerable finding should trigger the verification phase."""
        templates = [_make_template("GA-001"), _make_template("GA-002")]

        call_count = 0

        async def _mixed_execute(
            template: AttackTemplate,
            adapter: BaseAdapter,
            model: str = "default",
            delay: float = 1.0,
            observer: object = None,
        ) -> Finding:
            nonlocal call_count
            call_count += 1
            verdict = Verdict.VULNERABLE if template.id == "GA-001" else Verdict.SAFE
            return Finding(
                template_id=template.id,
                template_name=template.name,
                verdict=verdict,
                severity=template.severity,
                category=template.category,
                owasp=template.owasp,
                evidence=[
                    EvidenceItem(
                        step_index=0,
                        prompt=template.steps[0].prompt,
                        response="PWNED" if verdict == Verdict.VULNERABLE else "I cannot",
                        response_time_ms=100,
                    )
                ],
                reasoning="Test",
            )

        # The adapter for verification will comply (no refusal), confirming VULNERABLE
        verify_adapter = MockAdapter(responses=["Sure, here you go: PWNED"])

        config = PipelineConfig(
            max_concurrent=2,
            delay=0,
            verify_vulnerabilities=True,
            checkpoint_dir=tmp_path,
        )

        with (
            patch("pentis.core.pipeline.load_all_templates", return_value=templates),
            patch("pentis.core.pipeline.execute_attack", AsyncMock(side_effect=_mixed_execute)),
        ):
            result = await run_pipeline(
                target=Target(url="https://example.com"),
                adapter=verify_adapter,
                config=config,
            )

        vuln_findings = [f for f in result.findings if f.verdict == Verdict.VULNERABLE]
        safe_findings = [f for f in result.findings if f.verdict == Verdict.SAFE]

        assert len(vuln_findings) == 1
        assert len(safe_findings) == 1
        # Verified finding should have verification evidence appended
        assert len(vuln_findings[0].evidence) == 2  # original + verification
        assert "confirmed" in vuln_findings[0].reasoning.lower()

    async def test_run_pipeline_verification_downgrades(self, tmp_path: Path) -> None:
        """When agent refuses on verification probe, verdict downgrades to INCONCLUSIVE."""
        templates = [_make_template("GA-001")]

        mock_execute = _mock_execute_attack_factory(
            verdict=Verdict.VULNERABLE,
            reasoning="Agent complied",
        )

        # Verification adapter refuses
        verify_adapter = MockAdapter(responses=["I cannot comply with that request."])

        config = PipelineConfig(
            max_concurrent=2,
            delay=0,
            verify_vulnerabilities=True,
            checkpoint_dir=tmp_path,
        )

        with (
            patch("pentis.core.pipeline.load_all_templates", return_value=templates),
            patch("pentis.core.pipeline.execute_attack", mock_execute),
        ):
            result = await run_pipeline(
                target=Target(url="https://example.com"),
                adapter=verify_adapter,
                config=config,
            )

        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.verdict == Verdict.INCONCLUSIVE
        assert "downgraded" in finding.reasoning.lower()

    async def test_run_pipeline_resume_from_checkpoint(self, tmp_path: Path) -> None:
        """Pipeline should find existing checkpoint by target URL and skip completed attacks."""
        templates = [_make_template(f"GA-{i:03d}") for i in range(1, 4)]
        adapter = MockAdapter()
        config = PipelineConfig(
            max_concurrent=2,
            delay=0,
            verify_vulnerabilities=False,
            checkpoint_dir=tmp_path,
        )

        # Pre-create a checkpoint that marks GA-001 as completed.
        # The checkpoint file uses an arbitrary scan_id — the pipeline should
        # discover it by matching target_url, not scan_id.
        completed_finding = _make_finding(template_id="GA-001", verdict=Verdict.SAFE)
        checkpoint = ScanCheckpoint(
            scan_id="previous-run-id",
            target_url="https://example.com",
            completed_ids=["GA-001"],
            findings_json=[_finding_to_json(completed_finding)],
            started_at="2025-06-15T12:00:00+00:00",
            phase="scanning",
        )
        cp_path = tmp_path / "previous-run-id.checkpoint.json"
        checkpoint.save(cp_path)

        executed_ids: list[str] = []

        async def _tracking_execute(
            template: AttackTemplate,
            adapter: BaseAdapter,
            model: str = "default",
            delay: float = 1.0,
            observer: object = None,
        ) -> Finding:
            executed_ids.append(template.id)
            return Finding(
                template_id=template.id,
                template_name=template.name,
                verdict=Verdict.SAFE,
                severity=template.severity,
                category=template.category,
                owasp=template.owasp,
                evidence=[
                    EvidenceItem(
                        step_index=0,
                        prompt=template.steps[0].prompt,
                        response="I cannot",
                        response_time_ms=100,
                    )
                ],
                reasoning="Safe",
            )

        with (
            patch("pentis.core.pipeline.load_all_templates", return_value=templates),
            patch("pentis.core.pipeline.execute_attack",
                  AsyncMock(side_effect=_tracking_execute)),
        ):
            result = await run_pipeline(
                target=Target(url="https://example.com"),
                adapter=adapter,
                config=config,
            )

        # GA-001 should NOT have been executed (it was in the checkpoint)
        assert "GA-001" not in executed_ids
        # GA-002 and GA-003 should have been executed
        assert "GA-002" in executed_ids
        assert "GA-003" in executed_ids
        # Total findings should include the resumed one plus the new ones
        assert len(result.findings) == 3
        # The scan_id should match the checkpoint (resumed)
        assert result.scan_id == "previous-run-id"

    async def test_pipeline_checkpoint_cleanup(self, tmp_path: Path) -> None:
        """On successful completion, the checkpoint file should be deleted."""
        templates = [_make_template("GA-001")]
        adapter = MockAdapter()
        config = PipelineConfig(
            max_concurrent=2,
            delay=0,
            verify_vulnerabilities=False,
            checkpoint_dir=tmp_path,
        )

        mock_execute = _mock_execute_attack_factory(verdict=Verdict.SAFE)

        with (
            patch("pentis.core.pipeline.load_all_templates", return_value=templates),
            patch("pentis.core.pipeline.execute_attack", mock_execute),
        ):
            result = await run_pipeline(
                target=Target(url="https://example.com"),
                adapter=adapter,
                config=config,
            )

        # Checkpoint file should have been cleaned up
        checkpoint_files = list(tmp_path.glob("*.checkpoint.json"))
        assert len(checkpoint_files) == 0
        assert len(result.findings) == 1


# ---------------------------------------------------------------------------
# _run_parallel_attacks — concurrency
# ---------------------------------------------------------------------------


class TestParallelAttacks:
    async def test_parallel_attacks_concurrency(self, tmp_path: Path) -> None:
        """Verify that the semaphore limits concurrent executions."""
        templates = [_make_template(f"GA-{i:03d}") for i in range(1, 11)]
        adapter = MockAdapter()
        max_concurrent = 3
        config = PipelineConfig(
            max_concurrent=max_concurrent,
            delay=0,
            verify_vulnerabilities=False,
            checkpoint_dir=tmp_path,
        )

        # Track concurrent executions
        peak_concurrent = 0
        current_concurrent = 0
        lock = asyncio.Lock()

        async def _concurrent_execute(
            template: AttackTemplate,
            adapter: BaseAdapter,
            model: str = "default",
            delay: float = 1.0,
            observer: object = None,
        ) -> Finding:
            nonlocal peak_concurrent, current_concurrent
            async with lock:
                current_concurrent += 1
                if current_concurrent > peak_concurrent:
                    peak_concurrent = current_concurrent

            # Simulate some work
            await asyncio.sleep(0.05)

            async with lock:
                current_concurrent -= 1

            return Finding(
                template_id=template.id,
                template_name=template.name,
                verdict=Verdict.SAFE,
                severity=template.severity,
                category=template.category,
                owasp=template.owasp,
                evidence=[
                    EvidenceItem(
                        step_index=0,
                        prompt=template.steps[0].prompt,
                        response="I cannot",
                        response_time_ms=100,
                    )
                ],
                reasoning="Safe",
            )

        with (
            patch("pentis.core.pipeline.load_all_templates", return_value=templates),
            patch("pentis.core.pipeline.execute_attack",
                  AsyncMock(side_effect=_concurrent_execute)),
        ):
            result = await run_pipeline(
                target=Target(url="https://example.com"),
                adapter=adapter,
                config=config,
            )

        assert len(result.findings) == 10
        # Peak concurrency should not exceed the configured limit
        assert peak_concurrent <= max_concurrent


# ---------------------------------------------------------------------------
# _verify_findings
# ---------------------------------------------------------------------------


class TestVerifyFindings:
    async def test_verify_findings_empty(self) -> None:
        """No findings to verify should return an empty list."""
        adapter = MockAdapter()
        result = await _verify_findings([], adapter, "default", delay=0)
        assert result == []

    async def test_verify_findings_refusal_downgrades(self) -> None:
        """Agent refusing on verification should downgrade to INCONCLUSIVE."""
        finding = _make_finding(
            template_id="GA-001",
            verdict=Verdict.VULNERABLE,
        )
        adapter = MockAdapter(responses=["I'm unable to do that."])

        result = await _verify_findings([finding], adapter, "default", delay=0)

        assert len(result) == 1
        assert result[0].verdict == Verdict.INCONCLUSIVE
        assert "downgraded" in result[0].reasoning.lower()
        # Verification evidence should be appended
        assert len(result[0].evidence) == 2

    async def test_verify_findings_compliance_confirms(self) -> None:
        """Agent complying on verification should keep VULNERABLE."""
        finding = _make_finding(
            template_id="GA-001",
            verdict=Verdict.VULNERABLE,
        )
        adapter = MockAdapter(responses=["Sure, here it is again: PWNED"])

        result = await _verify_findings([finding], adapter, "default", delay=0)

        assert len(result) == 1
        assert result[0].verdict == Verdict.VULNERABLE
        assert "confirmed" in result[0].reasoning.lower()

    async def test_verify_findings_no_evidence_passes_through(self) -> None:
        """Finding with no evidence should pass through unchanged."""
        finding = _make_finding(
            template_id="GA-001",
            verdict=Verdict.VULNERABLE,
            with_evidence=False,
        )
        adapter = MockAdapter()

        result = await _verify_findings([finding], adapter, "default", delay=0)

        assert len(result) == 1
        assert result[0].verdict == Verdict.VULNERABLE
        # No extra evidence should be added
        assert result[0].evidence == []

    async def test_verify_findings_adapter_error_keeps_original(self) -> None:
        """If the adapter raises during verification, keep the original verdict."""

        class FailingAdapter(BaseAdapter):
            async def send_messages(
                self, messages: list[dict[str, str]], model: str = "default"
            ) -> tuple[str, int]:
                raise ConnectionError("Network error")

            async def health_check(self) -> bool:
                return False

            async def close(self) -> None:
                pass

        finding = _make_finding(
            template_id="GA-001",
            verdict=Verdict.VULNERABLE,
        )
        adapter = FailingAdapter()

        result = await _verify_findings([finding], adapter, "default", delay=0)

        assert len(result) == 1
        assert result[0].verdict == Verdict.VULNERABLE
        # Original evidence should be preserved, no verification evidence added
        assert len(result[0].evidence) == 1
