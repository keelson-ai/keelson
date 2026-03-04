# /pentis:report — Generate or Reformat Report

Regenerate or reformat a security scan report from previous findings.

## Usage

```
/pentis:report [report-file]
```

**Arguments** (from `$ARGUMENTS`):
- `[report-file]` — Path to an existing report to reformat (optional). If omitted, uses the most recent report in `reports/`.

## Instructions

1. **Find the report**:
   - If a path is provided in `$ARGUMENTS`, read that file
   - Otherwise, find the most recent `.md` file in `reports/`

2. **Read the report** and parse all findings.

3. **Regenerate the report** with:
   - Executive summary with risk score
   - Findings grouped by severity (Critical → High → Medium → Low)
   - OWASP LLM Top 10 mapping
   - Actionable remediation recommendations prioritized by severity
   - Statistics: total attacks, vulnerable count, safe count, pass rate

4. **Save** the reformatted report as `reports/report-YYYY-MM-DD-HHMMSS.md`.

5. **Display** the summary to the user.
