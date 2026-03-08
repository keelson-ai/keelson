# TypeScript Standards

## Tooling
- **Type checker**: tsc (strict mode, ESM-only, NodeNext)
- **Tests**: Vitest with nock for HTTP mocking
- **Package manager**: pnpm
- **Build**: tsc → dist/

## Code Style
- Type-annotate all public function signatures
- Use interfaces for data shapes, enums for fixed value sets
- Prefer functions and modules over class hierarchies
- Use `node:fs/promises` and `node:path` (node: prefix)
- Use axios for HTTP with retry interceptors
- All imports use `.js` extensions (NodeNext resolution)

## Conventions
- Imports: node builtins, then third-party, then local
- No wildcard imports (`from x import *`)
- camelCase for properties/variables, PascalCase for types/classes
- Zod schemas for runtime validation of external data (snake_case matching source)
- Types barrel in `src/types/index.ts` — single source of truth
- No mutable default arguments

## Testing
- Test files mirror source structure: `src/core/engine.ts` → `tests/core/engine.test.ts`
- Use `nock` for mocking HTTP calls
- Use Vitest `describe`/`it`/`expect`
- Test files use `.test.ts` suffix

## What to Avoid
- Overly abstract class hierarchies
- ABCs/interfaces unless there are 3+ implementations
- Premature abstractions or utility modules for one-off logic
- `// @ts-ignore` without explanation
- Bare `catch` without proper error handling
- `any` type without justification
