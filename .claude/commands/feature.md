# Feature Development Command

Systematic 7-phase approach to building new Pentis features.

## Usage
```
/feature <description>
```

## The 7 Phases

### Phase 1: Discovery
- Clarify the feature request
- Identify what problem it solves
- Identify constraints and requirements

### Phase 2: Codebase Exploration
- Explore similar features in the codebase
- Understand existing architecture and patterns
- Identify key files to read

### Phase 3: Clarifying Questions
- Review codebase findings and feature request
- Identify underspecified aspects (edge cases, integration points)
- Present all questions in an organized list
- **Wait for answers before proceeding**

### Phase 4: Architecture Design
Consider multiple approaches:
- **Minimal changes**: Smallest change, maximum reuse
- **Clean architecture**: Maintainability, elegant abstractions
- **Pragmatic balance**: Speed + quality
Present comparison with trade-offs and recommendation

### Phase 5: Implementation
- **Wait for explicit approval before starting**
- Read all relevant files identified in previous phases
- Follow codebase conventions (dataclasses, async httpx, YAML templates)
- Write clean, well-documented code

### Phase 6: Quality Review
- Simplicity/DRY
- Bugs/Correctness
- Conventions/Abstractions
- Run all tests: `pytest tests/ -v`

### Phase 7: Summary
- Summarize what was built
- Key decisions made
- Files modified
- Suggested next steps

The feature description is: $ARGUMENTS
