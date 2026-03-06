"""Parallel scan pipeline with checkpoint/resume."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pentis.adapters.base import BaseAdapter
from pentis.core.execution import apply_verified_findings, execute_parallel, verify_findings
from pentis.core.models import (
    Category,
    EvidenceItem,
    Finding,
    LeakageSignal,
    ScanResult,
    Severity,
    Target,
    Verdict,
)
from pentis.core.templates import load_all_templates

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for the parallel scan pipeline."""

    max_concurrent: int = 5
    delay: float = 1.5
    checkpoint_dir: Path | None = None
    verify_vulnerabilities: bool = True
    on_finding: Callable[[Finding, int, int], None] | None = None


# Checkpoint schema version — increment when checkpoint format changes
_CHECKPOINT_VERSION = 2


@dataclass
class ScanCheckpoint:
    """Persistent checkpoint for resuming interrupted scans."""

    scan_id: str
    target_url: str
    completed_ids: list[str] = field(default_factory=list[str])
    findings_json: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    started_at: str = ""
    phase: str = "scanning"
    version: int = _CHECKPOINT_VERSION

    def save(self, path: Path) -> None:
        """Persist checkpoint to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": self.version,
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "completed_ids": self.completed_ids,
            "findings_json": self.findings_json,
            "started_at": self.started_at,
            "phase": self.phase,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.replace(path)
        logger.debug("Checkpoint saved to %s (%d completed)", path, len(self.completed_ids))

    @classmethod
    def load(cls, path: Path) -> ScanCheckpoint:
        """Load a checkpoint from a JSON file.

        Raises ValueError if the checkpoint version doesn't match the current schema.
        """
        data = json.loads(path.read_text())
        stored_version = data.get("version", 1)
        if stored_version != _CHECKPOINT_VERSION:
            raise ValueError(
                f"Checkpoint version mismatch: file has v{stored_version}, "
                f"expected v{_CHECKPOINT_VERSION}. Delete the checkpoint to start fresh."
            )
        return cls(
            scan_id=data["scan_id"],
            target_url=data["target_url"],
            completed_ids=data.get("completed_ids", []),
            findings_json=data.get("findings_json", []),
            started_at=data.get("started_at", ""),
            phase=data.get("phase", "scanning"),
            version=stored_version,
        )


def _finding_to_json(finding: Finding) -> dict[str, object]:
    """Serialize a Finding to a JSON-compatible dict."""
    return {
        "template_id": finding.template_id,
        "template_name": finding.template_name,
        "verdict": str(finding.verdict),
        "severity": str(finding.severity),
        "category": str(finding.category),
        "owasp": finding.owasp,
        "reasoning": finding.reasoning,
        "timestamp": finding.timestamp.isoformat(),
        "evidence": [
            {
                "step_index": e.step_index,
                "prompt": e.prompt,
                "response": e.response,
                "response_time_ms": e.response_time_ms,
            }
            for e in finding.evidence
        ],
        "leakage_signals": [
            {
                "step_index": s.step_index,
                "signal_type": s.signal_type,
                "severity": s.severity,
                "description": s.description,
                "confidence": s.confidence,
            }
            for s in finding.leakage_signals
        ],
    }


def _get_str(d: dict[str, object], key: str, default: str = "") -> str:
    return str(d.get(key, default))


def _get_int(d: dict[str, object], key: str, default: int = 0) -> int:
    return int(str(d.get(key, default)))


def _get_float(d: dict[str, object], key: str, default: float = 0.0) -> float:
    return float(str(d.get(key, default)))


def _finding_from_json(data: dict[str, object]) -> Finding:
    """Deserialize a Finding from a JSON-compatible dict."""
    evidence_raw: list[dict[str, object]] = data.get("evidence", [])  # type: ignore[assignment]
    evidence = [
        EvidenceItem(
            step_index=_get_int(e, "step_index"),
            prompt=_get_str(e, "prompt"),
            response=_get_str(e, "response"),
            response_time_ms=_get_int(e, "response_time_ms"),
        )
        for e in evidence_raw
    ]

    signals_raw: list[dict[str, object]] = data.get("leakage_signals", [])  # type: ignore[assignment]
    leakage_signals = [
        LeakageSignal(
            step_index=_get_int(s, "step_index"),
            signal_type=_get_str(s, "signal_type"),
            severity=_get_str(s, "severity"),
            description=_get_str(s, "description"),
            confidence=_get_float(s, "confidence"),
        )
        for s in signals_raw
    ]

    ts_str = _get_str(data, "timestamp")
    try:
        timestamp = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        timestamp = datetime.now(UTC)

    return Finding(
        template_id=_get_str(data, "template_id"),
        template_name=_get_str(data, "template_name"),
        verdict=Verdict(_get_str(data, "verdict", "INCONCLUSIVE")),
        severity=Severity(_get_str(data, "severity", "Medium")),
        category=Category(_get_str(data, "category", "Goal Adherence")),
        owasp=_get_str(data, "owasp"),
        evidence=evidence,
        reasoning=_get_str(data, "reasoning"),
        timestamp=timestamp,
        leakage_signals=leakage_signals,
    )


def _checkpoint_path(config: PipelineConfig, scan_id: str) -> Path | None:
    """Return the checkpoint file path, or None if checkpointing is disabled."""
    if config.checkpoint_dir is None:
        return None
    return config.checkpoint_dir / f"{scan_id}.checkpoint.json"


def _find_existing_checkpoint(checkpoint_dir: Path, target_url: str) -> ScanCheckpoint | None:
    """Search checkpoint dir for an existing checkpoint matching the target URL."""
    if not checkpoint_dir.exists():
        return None
    candidates: list[tuple[Path, ScanCheckpoint]] = []
    for cp_file in checkpoint_dir.glob("*.checkpoint.json"):
        try:
            cp = ScanCheckpoint.load(cp_file)
            if cp.target_url == target_url:
                candidates.append((cp_file, cp))
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0].stat().st_mtime, reverse=True)
    return candidates[0][1]


async def run_pipeline(
    target: Target,
    adapter: BaseAdapter,
    config: PipelineConfig | None = None,
    attacks_dir: Path | None = None,
    category: str | None = None,
) -> ScanResult:
    """Run a parallel scan pipeline.

    Phases:
        1. Discovery  -- load templates and restore checkpoint
        2. Scanning   -- parallel attack execution with checkpointing
        3. Verification -- re-probe VULNERABLE findings to confirm
        4. Reporting  -- assemble final ScanResult
    """
    if config is None:
        config = PipelineConfig()

    # --- Phase 1: Discovery ---
    logger.info("Phase 1/4: Discovery — loading attack templates")
    templates = load_all_templates(attacks_dir=attacks_dir, category=category)
    if not templates:
        logger.warning("No attack templates found")
        return ScanResult(target=target, finished_at=datetime.now(UTC))

    logger.info("Loaded %d attack templates", len(templates))

    result = ScanResult(target=target)

    # Search for an existing checkpoint for this target URL
    existing_cp: ScanCheckpoint | None = None
    if config.checkpoint_dir is not None:
        existing_cp = _find_existing_checkpoint(config.checkpoint_dir, target.url)

    if existing_cp is not None:
        result.scan_id = existing_cp.scan_id

    cp_path = _checkpoint_path(config, result.scan_id)

    # Attempt checkpoint resume
    checkpoint = ScanCheckpoint(
        scan_id=result.scan_id,
        target_url=target.url,
        started_at=result.started_at.isoformat(),
        phase="scanning",
    )

    resumed_findings: list[Finding] = []
    if cp_path is not None and cp_path.exists():
        try:
            checkpoint = ScanCheckpoint.load(cp_path)
            result.scan_id = checkpoint.scan_id
            resumed_findings = [_finding_from_json(f) for f in checkpoint.findings_json]
            logger.info(
                "Resumed checkpoint: %d/%d attacks completed (phase=%s)",
                len(checkpoint.completed_ids),
                len(templates),
                checkpoint.phase,
            )
        except ValueError as exc:
            logger.warning("Incompatible checkpoint at %s: %s — starting fresh", cp_path, exc)
        except (json.JSONDecodeError, KeyError):
            logger.warning("Corrupt checkpoint at %s — starting fresh", cp_path)
            checkpoint = ScanCheckpoint(
                scan_id=result.scan_id,
                target_url=target.url,
                started_at=result.started_at.isoformat(),
                phase="scanning",
            )

    # Filter out already-completed templates
    remaining = [t for t in templates if t.id not in checkpoint.completed_ids]
    logger.info(
        "Phase 2/4: Scanning — %d remaining attacks (concurrency=%d)",
        len(remaining),
        config.max_concurrent,
    )

    # --- Phase 2: Scanning ---
    checkpoint.phase = "scanning"

    def _checkpointing_callback(finding: Finding, current: int, total: int) -> None:
        checkpoint.completed_ids.append(finding.template_id)
        checkpoint.findings_json.append(_finding_to_json(finding))
        if cp_path is not None:
            checkpoint.save(cp_path)
        if config.on_finding is not None:
            config.on_finding(finding, current, total)

    scan_findings = await execute_parallel(
        remaining,
        adapter,
        model=target.model,
        delay=config.delay,
        max_concurrent=config.max_concurrent,
        on_finding=_checkpointing_callback,
        offset=len(checkpoint.completed_ids),
        total=len(templates),
    )

    all_findings = resumed_findings + scan_findings

    # --- Phase 3: Verification ---
    if config.verify_vulnerabilities:
        checkpoint.phase = "verification"
        if cp_path is not None:
            checkpoint.save(cp_path)

        vulnerable = [f for f in all_findings if f.verdict == Verdict.VULNERABLE]
        if vulnerable:
            logger.info(
                "Phase 3/4: Verification — re-probing %d vulnerable findings",
                len(vulnerable),
            )
            verified = await verify_findings(
                vulnerable,
                adapter,
                model=target.model,
                delay=config.delay,
            )
            all_findings = apply_verified_findings(all_findings, verified)
        else:
            logger.info("Phase 3/4: Verification — no vulnerable findings to verify")
    else:
        logger.info("Phase 3/4: Verification — skipped (disabled)")

    # --- Phase 4: Reporting ---
    logger.info("Phase 4/4: Reporting — assembling results")
    result.findings = all_findings
    result.finished_at = datetime.now(UTC)

    vuln_count = sum(1 for f in all_findings if f.verdict == Verdict.VULNERABLE)
    safe_count = sum(1 for f in all_findings if f.verdict == Verdict.SAFE)
    inconc_count = sum(1 for f in all_findings if f.verdict == Verdict.INCONCLUSIVE)
    logger.info(
        "Scan complete: %d findings (%d vulnerable, %d safe, %d inconclusive)",
        len(all_findings),
        vuln_count,
        safe_count,
        inconc_count,
    )

    # Clean up checkpoint on successful completion
    if cp_path is not None and cp_path.exists():
        cp_path.unlink()
        logger.debug("Checkpoint cleaned up: %s", cp_path)

    return result
