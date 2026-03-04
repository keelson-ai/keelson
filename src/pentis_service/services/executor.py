"""Scan executor — runs scan campaigns as background tasks with progress tracking."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from pentis.adapters.factory import make_adapter
from pentis.campaign.runner import run_campaign
from pentis.core.models import (
    CampaignConfig,
    ConcurrencyConfig,
    Finding,
    ScanJob,
    ScanResult,
    ScanStatus,
    StatisticalFinding,
    Target,
)
from pentis.core.scanner import run_scan
from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus

logger = logging.getLogger(__name__)


class ScanExecutor:
    """Manages background scan execution with concurrency control."""

    def __init__(
        self,
        store: Store,
        event_bus: EventBus,
        max_concurrent: int = 3,
    ) -> None:
        self._store = store
        self._event_bus = event_bus
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._tasks: dict[str, asyncio.Task[None]] = {}

    async def submit_scan(
        self,
        job: ScanJob,
        api_key: str = "",
        model: str = "default",
        adapter_type: str = "openai",
        category: str | None = None,
        tier: str = "deep",
        delay: float = 1.5,
    ) -> str:
        """Submit a scan for background execution. Returns scan_id."""
        self._store.save_scan_job(job)
        await self._event_bus.publish("scan_queued", {"scan_id": job.scan_id})

        task = asyncio.create_task(
            self._run_scan(job, api_key, model, adapter_type, category, tier, delay)
        )
        self._tasks[job.scan_id] = task
        return job.scan_id

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            self._store.update_scan_job_status(scan_id, ScanStatus.CANCELLED)
            await self._event_bus.publish("scan_cancelled", {"scan_id": scan_id})
            return True
        return False

    async def _run_scan(
        self,
        job: ScanJob,
        api_key: str,
        model: str,
        adapter_type: str,
        category: str | None,
        tier: str,
        delay: float,
    ) -> None:
        """Execute a scan with semaphore-based concurrency control."""
        async with self._semaphore:
            self._store.update_scan_job_status(job.scan_id, ScanStatus.RUNNING)
            await self._event_bus.publish(
                "scan_started", {"scan_id": job.scan_id, "target": job.target_url}
            )

            adapter = make_adapter(url=job.target_url, api_key=api_key, adapter_type=adapter_type)
            target = Target(url=job.target_url, api_key=api_key, model=model)

            try:
                if tier == "fast":
                    result = await self._run_simple_scan(
                        job, target, adapter, model, category, delay
                    )
                else:
                    result = await self._run_campaign_scan(
                        job, target, adapter, model, category, tier, delay
                    )

                self._store.save_scan(result)
                self._store.update_scan_job_status(
                    job.scan_id,
                    ScanStatus.COMPLETED,
                    progress=job.total_attacks,
                    vulnerable_count=result.vulnerable_count,
                )
                await self._event_bus.publish(
                    "scan_completed",
                    {
                        "scan_id": job.scan_id,
                        "vulnerable": result.vulnerable_count,
                        "safe": result.safe_count,
                        "inconclusive": result.inconclusive_count,
                    },
                )
            except asyncio.CancelledError:
                logger.info("Scan cancelled: %s", job.scan_id)
                raise
            except Exception as exc:
                logger.exception("Scan failed: %s", job.scan_id)
                self._store.update_scan_job_status(
                    job.scan_id, ScanStatus.FAILED, error_message=str(exc)
                )
                await self._event_bus.publish(
                    "scan_failed", {"scan_id": job.scan_id, "error": str(exc)}
                )
            finally:
                await adapter.close()
                self._tasks.pop(job.scan_id, None)

    async def _run_simple_scan(
        self,
        job: ScanJob,
        target: Target,
        adapter: object,
        model: str,
        category: str | None,
        delay: float,
    ) -> ScanResult:
        """Run a simple single-pass scan."""
        from pentis.adapters.base import BaseAdapter

        assert isinstance(adapter, BaseAdapter)
        vuln_count = 0

        def on_finding(finding: Finding, current: int, total: int) -> None:
            nonlocal vuln_count
            if finding.verdict.value == "VULNERABLE":
                vuln_count += 1
            self._store.update_scan_job_status(
                job.scan_id, ScanStatus.RUNNING, progress=current, vulnerable_count=vuln_count
            )

        result = await run_scan(
            target=target,
            adapter=adapter,
            category=category,
            delay=delay,
            on_finding=on_finding,
        )
        return result

    async def _run_campaign_scan(
        self,
        job: ScanJob,
        target: Target,
        adapter: object,
        model: str,
        category: str | None,
        tier: str,
        delay: float,
    ) -> ScanResult:
        """Run a statistical campaign scan and convert to ScanResult."""
        from pentis.adapters.base import BaseAdapter
        from pentis.campaign.tiers import get_tier_config
        from pentis.core.models import ScanTier

        assert isinstance(adapter, BaseAdapter)
        tier_enum = ScanTier(tier) if tier in {t.value for t in ScanTier} else ScanTier.DEEP
        config = get_tier_config(tier_enum)
        config.name = f"service-{job.scan_id}"
        config.category = category
        config.target_url = job.target_url
        config.api_key = target.api_key
        config.model = model
        vuln_count = 0

        def on_finding(sf: StatisticalFinding, current: int, total: int) -> None:
            nonlocal vuln_count
            if sf.verdict.value == "VULNERABLE":
                vuln_count += 1
            self._store.update_scan_job_status(
                job.scan_id, ScanStatus.RUNNING, progress=current, vulnerable_count=vuln_count
            )

        campaign_result = await run_campaign(
            target=target,
            adapter=adapter,
            config=config,
            on_finding=on_finding,
        )

        # Convert campaign to ScanResult for unified storage
        findings = []
        for sf in campaign_result.findings:
            best_trial = next(
                (t for t in sf.trials if t.verdict == sf.verdict), sf.trials[0] if sf.trials else None
            )
            if best_trial:
                from pentis.core.models import Finding as FindingModel

                findings.append(
                    FindingModel(
                        template_id=sf.template_id,
                        template_name=sf.template_name,
                        verdict=sf.verdict,
                        severity=sf.severity,
                        category=sf.category,
                        owasp=sf.owasp,
                        evidence=best_trial.evidence,
                        reasoning=best_trial.reasoning,
                    )
                )

        return ScanResult(
            scan_id=job.scan_id,
            target=target,
            findings=findings,
            started_at=campaign_result.started_at,
            finished_at=datetime.now(timezone.utc),
        )
