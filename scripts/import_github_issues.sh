#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-Pentis-AI/Pentis-Monorepo}"
CSV_PATH="${2:-.github/backlog/week1-4-issues.csv}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found"
  exit 1
fi

if ! gh auth status -h github.com >/dev/null 2>&1; then
  echo "gh is not authenticated. Run: gh auth login -h github.com"
  exit 1
fi

# Skip header line, parse RFC4180-style via python csv module to avoid shell parsing bugs.
python3 - "$CSV_PATH" <<'PY' | while IFS=$'\t' read -r title body labels milestone; do
import csv, sys
path = sys.argv[1]
with open(path, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        print("\t".join([row["title"], row["body"], row["labels"], row["milestone"]]))
PY
  label_args=()
  IFS=',' read -r -a label_list <<< "$labels"
  for label in "${label_list[@]}"; do
    clean_label="$(echo "$label" | xargs)"
    if [[ -n "$clean_label" ]]; then
      label_args+=(--label "$clean_label")
    fi
  done
  if [[ -n "$milestone" ]]; then
    gh issue create --repo "$REPO" --title "$title" --body "$body" "${label_args[@]}" --milestone "$milestone"
  else
    gh issue create --repo "$REPO" --title "$title" --body "$body" "${label_args[@]}"
  fi
  echo "Created: $title"
done
