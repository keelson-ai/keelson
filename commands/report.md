# /keelson:report — Generate or Reformat Report

Regenerate or reformat a security scan report from previous findings.

## Usage

```
/keelson:report [report-file]
```

**Arguments** (from `$ARGUMENTS`):

- `[report-file]` — Path to an existing report to reformat (optional). If omitted, uses the most recent report in `reports/`.

## Instructions

1. **Find the report**:
   - If a path is provided in `$ARGUMENTS`, read that file
   - Otherwise, find the most recent `.md` file in `reports/`

2. **Read the report** and parse all findings.

3. **Regenerate the report** following `agents/reporter.md` methodology:
   - Executive summary with risk score
   - Target profile (if available in source report)
   - Research summary (if available)
   - Findings grouped by severity (Critical → High → Medium → Low)
   - Attack narrative for chained findings
   - OWASP LLM Top 10 mapping
   - Actionable remediation recommendations tied to specific probe IDs
   - Statistics: total probes, vulnerable count, safe count, pass rate
   - Adaptation log (if available in source report)
   - Skipped probes with rationale (if available)

4. **Save** the reformatted report as `reports/report-YYYY-MM-DD-HHMMSS.md`.

5. **Display** the summary to the user.
