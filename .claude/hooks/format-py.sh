#!/bin/bash
# PostToolUse hook to auto-format Python files

# Read JSON from stdin
input=$(cat)

# Extract file_path from tool_input
file_path=$(echo "$input" | jq -r '.tool_input.file_path // empty')

# If no file_path, try filePath
if [ -z "$file_path" ]; then
  file_path=$(echo "$input" | jq -r '.tool_input.filePath // empty')
fi

# Exit if no file path found
if [ -z "$file_path" ]; then
  exit 0
fi

# Only format Python files
if [[ "$file_path" == *.py ]]; then
  cd "$CLAUDE_PROJECT_DIR" 2>/dev/null || exit 0
  # Use ruff if available, otherwise skip
  if command -v ruff &>/dev/null; then
    ruff format "$file_path" 2>/dev/null
    ruff check --fix "$file_path" 2>/dev/null
  fi
fi

exit 0
