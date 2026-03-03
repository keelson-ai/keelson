# Code Review Command

Perform comprehensive code review using multiple perspectives.

## Usage
```
/code-review [pr-number or path]
```

## Review Process

1. **Gather context** from CLAUDE.md and project rules
2. **Summarize the changes**
3. **Launch parallel reviews**:
   - Audit for guideline compliance
   - Scan for bugs in changes
   - Analyze git blame/history for context
4. **Score each issue 0-100** for confidence level
5. **Filter out issues below 80 confidence threshold**
6. **Report high-confidence issues only**

## Confidence Scoring Scale
- **0**: Not confident, false positive
- **25**: Somewhat confident, might be real
- **50**: Moderately confident, real but minor
- **75**: Highly confident, real and important
- **100**: Absolutely certain, definitely real

## Review Focus Areas
- Project conventions compliance
- Bug detection (changes only, not pre-existing)
- Security vulnerabilities
- Performance implications
- Test coverage

## Implementation

The review target is: $ARGUMENTS
