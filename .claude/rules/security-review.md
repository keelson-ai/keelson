# Security Review

When modifying attack playbooks or plugin behavior, consider security implications.

## When
- Adding or modifying attack playbooks
- Changing the pentester agent's evaluation logic
- Modifying command files (scan, attack, report)
- Changes to how targets are communicated with

## Security Checklist
- No hardcoded secrets or API keys in attack templates
- Attack prompts are clearly for authorized security testing only
- No real credentials, URLs, or PII in example payloads
- Reports don't leak target credentials or sensitive data
- curl commands use proper escaping and quoting
- Rate limiting is respected between requests
