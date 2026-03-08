# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Keelson itself, please report it responsibly:

1. **Do NOT open a public issue.**
2. Use [GitHub Security Advisories](https://github.com/keelson-ai/keelson/security/advisories/new) to report privately.
3. Include steps to reproduce, impact assessment, and any suggested fix.

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

This policy covers vulnerabilities in the Keelson codebase itself — the scanner engine, CLI, adapters, and detection pipeline.

**Out of scope:**
- Vulnerabilities found *by* Keelson in target systems (that's what Keelson is for)
- Probe playbook content (these are intentionally adversarial prompts for authorized testing)

## Authorized Use

Keelson is designed for **authorized security testing only**. You must have explicit written permission before testing any system you do not own. Unauthorized use may violate applicable laws including the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act 1990, EU Directive 2013/40/EU, and equivalent laws in other jurisdictions.

The authors and contributors accept no liability for misuse of this software. See [LEGAL.md](LEGAL.md) for full terms, disclaimer of liability, indemnification obligations, and export compliance requirements.
