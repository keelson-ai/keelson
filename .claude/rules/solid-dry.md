# SOLID & DRY Principles

When writing or reviewing TypeScript code in `src/`, enforce these principles.

## When
- Adding new modules or classes
- Refactoring existing code
- Reviewing PRs that touch `src/**/*.ts`

## DRY (Don't Repeat Yourself)

- Extract shared logic when the same pattern appears 2+ times across functions or files
- Shared utilities belong in dedicated modules (e.g. `scan-helpers.ts` for scanner/convergence shared code)
- Error handling patterns (try/catch + sanitize + fallback) must be consistent across all code paths that call the same underlying function
- Constants used in multiple files must be defined once and imported (e.g. `SEVERITY_ORDER`)
- Group-and-sort patterns over collections should be extracted into helper functions

## SOLID

### Single Responsibility (SRP)
- Each module should have one primary concern. Split when a file exceeds ~300 LOC with distinct concerns
- Don't split prematurely — 3 related functions in one file is fine if they share the same abstraction level

### Open/Closed (OCP)
- Prefer data-driven configuration (maps, arrays) over switch/if chains for extensible behavior
- New probe categories, leakage patterns, or detection rules should be addable without modifying core logic

### Liskov Substitution (LSP)
- Implementations must satisfy their interface contract completely
- Don't add methods to interfaces that not all implementations need

### Interface Segregation (ISP)
- Keep interfaces minimal — only require what consumers actually call
- Lifecycle methods (`close`, `resetSession`) should be optional if not all consumers use them
- Use optional chaining (`adapter.resetSession?.()`) when calling optional interface methods

### Dependency Inversion (DIP)
- Core engine should depend on abstractions (`Adapter`, `Observer`), not concrete classes
- Inject dependencies through function parameters or options objects, not imports of concrete implementations

## What NOT to Do
- Don't extract a helper for a pattern that only appears once — that's premature abstraction
- Don't create deep inheritance hierarchies — prefer composition and interfaces
- Don't add `// type: ignore` to work around interface mismatches — fix the interface instead
- Don't duplicate error handling — if two code paths call the same function, share the try/catch pattern
