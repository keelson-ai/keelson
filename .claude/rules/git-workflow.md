# Git Workflow

**EVERY commit MUST be followed by automatic push and PR creation.**

## Required Workflow
```bash
# 1. Fetch latest
git fetch origin

# 2. Pull and merge (no rebase)
git pull origin main --no-rebase

# 3. Run lint and format BEFORE committing (MANDATORY)
uv run ruff check src/ tests/ --fix && uv run ruff format src/ tests/

# 4. Commit changes
git add <specific-files> && git commit -m "<type>: <description>"

# 5. Push to remote
git push origin <branch-name>

# 6. Create PR (MANDATORY)
gh pr create --title "<type>: <description>" --body "<summary>"
```

## Pre-Commit Lint Rule
**ALWAYS run `uv run ruff check src/ tests/ --fix && uv run ruff format src/ tests/` before every commit.**
This catches line-length violations, import sorting, and formatting issues before they reach CI.
Pre-commit hooks are configured in `.pre-commit-config.yaml` and must be installed via `uv run pre-commit install`.

## PR Title Format
```
<type>: <brief description>

Examples:
feat: Add multi-turn attack engine
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
