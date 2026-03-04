"""Regression detection service — compares scans against baselines."""

from __future__ import annotations

import logging

from pentis.core.models import RegressionAlert
from pentis.diff.comparator import enhanced_diff_scans
from pentis.state.store import Store
from pentis_service.services.event_bus import EventBus

logger = logging.getLogger(__name__)


class RegressionService:
    """Automatically compares new scans against baselines for regressions."""

    def __init__(self, store: Store, event_bus: EventBus) -> None:
        self._store = store
        self._event_bus = event_bus

    async def check_regression(self, scan_id: str) -> list[RegressionAlert]:
        """Compare a completed scan against the latest baseline for its target.

        Returns any regression alerts found.
        """
        scan = self._store.get_scan(scan_id)
        if not scan:
            logger.warning("Scan not found for regression check: %s", scan_id)
            return []

        # Find the most recent baseline for this target
        baselines = self._store.get_baselines()
        baseline_scan = None
        for bl in baselines:
            if bl["target_url"] == scan.target.url and bl["scan_id"] != scan_id:
                baseline_scan = self._store.get_scan(bl["scan_id"])
                if baseline_scan:
                    break

        if not baseline_scan:
            logger.info("No baseline found for target %s — skipping regression", scan.target.url)
            # Auto-set this scan as the first baseline
            self._store.save_baseline(scan_id, label="auto-baseline")
            return []

        diff, alerts = enhanced_diff_scans(baseline_scan, scan)

        if alerts:
            self._store.save_regression_alerts(baseline_scan.scan_id, scan_id, alerts)
            for alert in alerts:
                await self._event_bus.publish(
                    "regression_detected",
                    {
                        "scan_id": scan_id,
                        "baseline_id": baseline_scan.scan_id,
                        "template_id": alert.template_id,
                        "alert_severity": alert.alert_severity,
                        "description": alert.description,
                    },
                )
            logger.info(
                "Regression check: %d alerts for scan %s vs baseline %s",
                len(alerts),
                scan_id,
                baseline_scan.scan_id,
            )

        # Update baseline to this scan for next comparison
        self._store.save_baseline(scan_id, label="auto-baseline")
        return alerts
