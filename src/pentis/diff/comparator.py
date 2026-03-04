"""Scan diff and baseline comparison."""

from __future__ import annotations

from pentis.core.models import (
    CampaignResult,
    RegressionAlert,
    ScanDiff,
    ScanDiffItem,
    ScanResult,
    Severity,
    Verdict,
)


def diff_scans(scan_a: ScanResult, scan_b: ScanResult) -> ScanDiff:
    """Compare two scan results and produce a diff.

    scan_a is the 'before' scan, scan_b is the 'after' scan.
    """
    a_map = {f.template_id: f for f in scan_a.findings}
    b_map = {f.template_id: f for f in scan_b.findings}
    all_ids = sorted(set(a_map) | set(b_map))
    items: list[ScanDiffItem] = []

    for tid in all_ids:
        fa = a_map.get(tid)
        fb = b_map.get(tid)

        if fa and fb:
            if fa.verdict == fb.verdict:
                continue  # No change
            change = _classify_change(fa.verdict, fb.verdict)
            items.append(ScanDiffItem(
                template_id=tid,
                template_name=fb.template_name,
                old_verdict=fa.verdict,
                new_verdict=fb.verdict,
                change_type=change,
            ))
        elif fa and not fb:
            items.append(ScanDiffItem(
                template_id=tid,
                template_name=fa.template_name,
                old_verdict=fa.verdict,
                new_verdict=None,
                change_type="removed",
            ))
        else:  # fb and not fa
            items.append(ScanDiffItem(
                template_id=tid,
                template_name=fb.template_name,
                old_verdict=None,
                new_verdict=fb.verdict,
                change_type="new",
            ))

    return ScanDiff(scan_a_id=scan_a.scan_id, scan_b_id=scan_b.scan_id, items=items)


def _classify_change(old: Verdict, new: Verdict) -> str:
    """Classify a verdict change as regression or improvement."""
    severity = {Verdict.SAFE: 0, Verdict.INCONCLUSIVE: 1, Verdict.VULNERABLE: 2}
    if severity[new] > severity[old]:
        return "regression"
    return "improvement"


def diff_from_baseline(baseline: ScanResult, current: ScanResult) -> ScanDiff:
    """Compare current scan against a baseline scan."""
    return diff_scans(baseline, current)


def format_diff_report(diff: ScanDiff) -> str:
    """Format a scan diff as a readable markdown section."""
    lines = [f"## Scan Diff: {diff.scan_a_id} → {diff.scan_b_id}\n"]

    if not diff.items:
        lines.append("No changes detected.\n")
        return "\n".join(lines)

    if diff.regressions:
        lines.append("### Regressions\n")
        for item in diff.regressions:
            lines.append(
                f"- **{item.template_id}**: {item.template_name} — "
                f"{item.old_verdict.value if item.old_verdict else 'N/A'} → "
                f"{item.new_verdict.value if item.new_verdict else 'N/A'}"
            )
        lines.append("")

    if diff.improvements:
        lines.append("### Improvements\n")
        for item in diff.improvements:
            lines.append(
                f"- **{item.template_id}**: {item.template_name} — "
                f"{item.old_verdict.value if item.old_verdict else 'N/A'} → "
                f"{item.new_verdict.value if item.new_verdict else 'N/A'}"
            )
        lines.append("")

    new_items = [i for i in diff.items if i.change_type == "new"]
    removed_items = [i for i in diff.items if i.change_type == "removed"]

    if new_items:
        lines.append("### New Attacks\n")
        for item in new_items:
            lines.append(
                f"- **{item.template_id}**: {item.template_name} — "
                f"{item.new_verdict.value if item.new_verdict else 'N/A'}"
            )
        lines.append("")

    if removed_items:
        lines.append("### Removed Attacks\n")
        for item in removed_items:
            lines.append(
                f"- **{item.template_id}**: {item.template_name} — "
                f"was {item.old_verdict.value if item.old_verdict else 'N/A'}"
            )
        lines.append("")

    summary = (
        f"**Summary**: {len(diff.regressions)} regressions, "
        f"{len(diff.improvements)} improvements, "
        f"{len(new_items)} new, {len(removed_items)} removed"
    )
    lines.append(summary)
    return "\n".join(lines)


# --- Phase 3: Enhanced regression alerts ---


def classify_alert_severity(
    item: ScanDiffItem,
    attack_severity: Severity | None = None,
) -> str:
    """Classify the severity of a regression alert.

    Rules:
    - Critical: SAFE→VULNERABLE on Critical/High severity attack
    - High: new VULNERABLE attack or SAFE→VULNERABLE on Medium/Low
    - Medium: INCONCLUSIVE→VULNERABLE
    - Low: minor behavioral changes (e.g., SAFE→INCONCLUSIVE)
    """
    if item.change_type == "new" and item.new_verdict == Verdict.VULNERABLE:
        return "high"

    if item.old_verdict == Verdict.SAFE and item.new_verdict == Verdict.VULNERABLE:
        if attack_severity and attack_severity in (Severity.CRITICAL, Severity.HIGH):
            return "critical"
        return "high"

    if item.old_verdict == Verdict.INCONCLUSIVE and item.new_verdict == Verdict.VULNERABLE:
        return "medium"

    return "low"


def enhanced_diff_scans(
    scan_a: ScanResult,
    scan_b: ScanResult,
) -> tuple[ScanDiff, list[RegressionAlert]]:
    """Compare two scans with severity-classified regression alerts.

    Returns the standard ScanDiff plus a list of RegressionAlert objects.
    """
    diff = diff_scans(scan_a, scan_b)
    alerts: list[RegressionAlert] = []

    # Build severity lookup from scan_b findings
    severity_map = {f.template_id: f.severity for f in scan_b.findings}
    severity_map.update({f.template_id: f.severity for f in scan_a.findings})

    for item in diff.items:
        if item.change_type not in ("regression", "new"):
            continue
        # Only alert on items that became (more) vulnerable
        if item.new_verdict not in (Verdict.VULNERABLE, Verdict.INCONCLUSIVE):
            continue
        if item.change_type == "new" and item.new_verdict != Verdict.VULNERABLE:
            continue

        attack_sev = severity_map.get(item.template_id)
        alert_sev = classify_alert_severity(item, attack_sev)

        alerts.append(RegressionAlert(
            template_id=item.template_id,
            alert_severity=alert_sev,
            change_type=item.change_type,
            description=(
                f"{item.template_name}: "
                f"{item.old_verdict.value if item.old_verdict else 'N/A'} → "
                f"{item.new_verdict.value if item.new_verdict else 'N/A'}"
            ),
            old_verdict=item.old_verdict,
            new_verdict=item.new_verdict,
            attack_severity=attack_sev,
        ))

    # Sort alerts by severity: critical first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: severity_order.get(a.alert_severity, 4))

    return diff, alerts


def diff_campaigns(
    campaign_a: CampaignResult,
    campaign_b: CampaignResult,
) -> list[RegressionAlert]:
    """Compare two campaign results for statistical regressions.

    Detects rate increases between campaigns (e.g., attack that went from 10% to 60%).
    """
    alerts: list[RegressionAlert] = []

    a_map = {f.template_id: f for f in campaign_a.findings}
    b_map = {f.template_id: f for f in campaign_b.findings}

    for tid in sorted(set(a_map) | set(b_map)):
        fa = a_map.get(tid)
        fb = b_map.get(tid)

        if fa and fb:
            # Check for verdict regression
            if fa.verdict == Verdict.SAFE and fb.verdict == Verdict.VULNERABLE:
                alert_sev = "critical" if fb.severity in (Severity.CRITICAL, Severity.HIGH) else "high"
                alerts.append(RegressionAlert(
                    template_id=tid,
                    alert_severity=alert_sev,
                    change_type="regression",
                    description=(
                        f"{fb.template_name}: vulnerability rate increased from "
                        f"{fa.success_rate:.0%} to {fb.success_rate:.0%}"
                    ),
                    old_verdict=fa.verdict,
                    new_verdict=fb.verdict,
                    attack_severity=fb.severity,
                ))
            elif fa.verdict != Verdict.VULNERABLE and fb.verdict == Verdict.VULNERABLE:
                alerts.append(RegressionAlert(
                    template_id=tid,
                    alert_severity="medium",
                    change_type="regression",
                    description=(
                        f"{fb.template_name}: became statistically vulnerable "
                        f"({fb.success_rate:.0%} rate)"
                    ),
                    old_verdict=fa.verdict,
                    new_verdict=fb.verdict,
                    attack_severity=fb.severity,
                ))
            elif fb.success_rate > fa.success_rate + 0.2:
                # Significant rate increase even without verdict change
                alerts.append(RegressionAlert(
                    template_id=tid,
                    alert_severity="low",
                    change_type="rate_increase",
                    description=(
                        f"{fb.template_name}: vulnerability rate increased from "
                        f"{fa.success_rate:.0%} to {fb.success_rate:.0%}"
                    ),
                    old_verdict=fa.verdict,
                    new_verdict=fb.verdict,
                    attack_severity=fb.severity,
                ))
        elif fb and not fa:
            if fb.verdict == Verdict.VULNERABLE:
                alerts.append(RegressionAlert(
                    template_id=tid,
                    alert_severity="high",
                    change_type="new_vulnerable",
                    description=f"{fb.template_name}: new vulnerable attack ({fb.success_rate:.0%} rate)",
                    new_verdict=fb.verdict,
                    attack_severity=fb.severity,
                ))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: severity_order.get(a.alert_severity, 4))
    return alerts
