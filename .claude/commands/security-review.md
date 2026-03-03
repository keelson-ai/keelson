# Security Review Command

Perform a security-focused review of the Pentis codebase or a specific component.

## Usage
```
/security-review [path]
```

## Review Checklist
- [ ] No hardcoded secrets or credentials in code
- [ ] Input validation on all user/external data
- [ ] Safe handling of target agent responses (no eval, no injection)
- [ ] Proper error handling (no stack traces leaked)
- [ ] HTTP adapter handles auth tokens securely
- [ ] YAML template loading validates against schema
- [ ] Report generation sanitizes evidence content
- [ ] Dependencies up to date and free of known CVEs

## OWASP LLM Top 10 Coverage
- LLM01: Prompt Injection (Goal Adherence templates)
- LLM02: Insecure Output Handling (Tool Safety templates)
- LLM05: Supply Chain Vulnerabilities (Memory Integrity templates)
- LLM06: Excessive Agency (Tool Safety templates)

## Implementation

Review the specified path or entire `src/pentis/` directory for security issues.
The path argument is: $ARGUMENTS
