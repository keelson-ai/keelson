"""Scan diff and baseline comparison."""

from __future__ import annotations

from pentis.core.models import ScanDiff, ScanDiffItem, ScanResult, Verdict


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
