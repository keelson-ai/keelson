# No Vendor References

NEVER reference competitor products, external tools, or third-party inspirations in source code, comments, docstrings, or commit messages.

## When
- Writing or modifying any Python source code (`src/`, `tests/`)
- Writing commit messages or PR descriptions
- Adding comments or docstrings

## Rules
- No "inspired by", "based on", or "adapted from" references to external projects
- No competitor product names in code comments (e.g., no mentioning other security scanners, audit tools, or AI agents by name)
- No links to external repositories in source code comments
- Attack playbooks may use generic "vendor" references in attack prompts (these are attack content, not attribution)
- If a technique has an academic name (e.g., "PAIR", "crescendo"), use the technique name without attributing it to a specific tool

## Why
- Keelson is original work; code should stand on its own
- Vendor references create unnecessary associations
- Keep the codebase clean and professional
