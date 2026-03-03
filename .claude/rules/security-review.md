# Security Review

When security-sensitive changes are detected, suggest security review.

## When
- Changes to HTTP adapter (auth, headers, credentials)
- Changes to detection pipeline (input parsing, response handling)
- Changes to CLI (user input handling)
- Changes to report generation (evidence rendering)
- New dependencies added

## Security Checklist
- No hardcoded secrets or API keys
- Input validation on all external data
- Safe response handling (no eval, no injection)
- Proper error messages (no stack traces to users)
- Secure HTTP defaults (timeouts, TLS)
- Template loading validates against schema
- Dependencies free of known CVEs
