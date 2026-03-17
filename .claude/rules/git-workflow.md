# Git Workflow

**Do NOT commit, push, or create PRs.** The user handles all git operations.

## Pre-Commit Lint Rule

**ALWAYS run `pnpm lint` (type check) before telling the user the work is done.**
This catches type errors before they reach CI.

## PR Title Format

```
<type>: <brief description>

Examples:
feat: Add multi-turn probe engine
fix: Handle 429 rate limit in HTTP adapter
refactor: Extract detection pipeline into modules
test: Add integration tests for scanner
```

## Never

- `git push --force` without user approval
- `git reset --hard` on shared branches
- Skip conflict resolution
- Commit without PR
- Use `--no-verify` to skip hooks
