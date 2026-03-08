# Keelson GitHub Action Spec

## `keelson-ai/keelson-action@v1`

Composite GitHub Action that runs Keelson security scans against AI agent endpoints and uploads SARIF results to GitHub Code Scanning.

## Design

**Type**: Composite action (no Docker required)

### Inputs

| Input            | Required | Default   | Description                      |
|------------------|----------|-----------|----------------------------------|
| `target-url`     | Yes      | —         | AI agent endpoint URL            |
| `api-key`        | No       | —         | API key (use secrets)            |
| `model`          | No       | `default` | Model name                       |
| `adapter`        | No       | `openai`  | Adapter type                     |
| `category`       | No       | —         | Filter by category               |
| `tier`           | No       | `fast`    | Scan tier: fast, deep            |
| `format`         | No       | `sarif`   | Output format                    |
| `fail-on-vuln`   | No       | `true`    | Exit non-zero on vulnerabilities |
| `python-version` | No       | `3.12`    | Python version                   |

### Outputs

| Output             | Description                     |
|--------------------|---------------------------------|
| `sarif-file`       | Path to SARIF output file       |
| `vulnerable-count` | Number of vulnerabilities found |
| `scan-id`          | Keelson scan ID                  |

## Composite Action Steps

```yaml
# action.yml
name: 'Keelson AI Security Scan'
description: 'Run AI agent security testing with Keelson'
branding:
  icon: shield
  color: red

inputs:
  target-url:
    description: 'AI agent endpoint URL'
    required: true
  api-key:
    description: 'API key for target endpoint'
    required: false
  model:
    description: 'Model name for requests'
    default: 'default'
  adapter:
    description: 'Adapter type: openai, anthropic, langgraph, mcp'
    default: 'openai'
  category:
    description: 'Filter probes by category'
    required: false
  tier:
    description: 'Scan tier: fast or deep'
    default: 'fast'
  fail-on-vuln:
    description: 'Fail the step if vulnerabilities are found'
    default: 'true'
  python-version:
    description: 'Python version to use'
    default: '3.12'

outputs:
  sarif-file:
    description: 'Path to SARIF results file'
    value: ${{ steps.scan.outputs.sarif-file }}
  vulnerable-count:
    description: 'Number of vulnerabilities found'
    value: ${{ steps.scan.outputs.vulnerable-count }}

runs:
  using: 'composite'
  steps:
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: ${{ inputs.python-version }}

    - name: Install Keelson
      shell: bash
      run: pip install keelson

    - name: Run scan
      id: scan
      shell: bash
      env:
        KEELSON_API_KEY: ${{ inputs.api-key }}
      run: |
        ARGS="--format sarif --tier ${{ inputs.tier }} --adapter ${{ inputs.adapter }} --model ${{ inputs.model }}"
        if [ -n "$KEELSON_API_KEY" ]; then
          ARGS="$ARGS --api-key $KEELSON_API_KEY"
        fi
        if [ -n "${{ inputs.category }}" ]; then
          ARGS="$ARGS --category ${{ inputs.category }}"
        fi
        keelson scan ${{ inputs.target-url }} $ARGS --output results/ --no-save
        SARIF_FILE=$(ls results/*.sarif.json | head -1)
        echo "sarif-file=$SARIF_FILE" >> $GITHUB_OUTPUT
        VULN_COUNT=$(python -c "import json; d=json.load(open('$SARIF_FILE')); print(sum(1 for r in d['runs'][0]['results'] if r['kind']=='fail'))")
        echo "vulnerable-count=$VULN_COUNT" >> $GITHUB_OUTPUT

    - name: Upload SARIF
      if: always()
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: ${{ steps.scan.outputs.sarif-file }}

    - name: Check results
      if: inputs.fail-on-vuln == 'true'
      shell: bash
      run: |
        if [ "${{ steps.scan.outputs.vulnerable-count }}" -gt 0 ]; then
          echo "::error::Keelson found ${{ steps.scan.outputs.vulnerable-count }} vulnerabilities"
          exit 1
        fi
```

## Example CI Workflow

```yaml
# .github/workflows/ai-security.yml
name: AI Agent Security

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  keelson-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: keelson-ai/keelson-action@v1
        with:
          target-url: ${{ vars.AGENT_ENDPOINT }}
          api-key: ${{ secrets.AGENT_API_KEY }}
          tier: fast
          fail-on-vuln: true
```

## Advanced: Deep Scan with Category Filter

```yaml
jobs:
  keelson-deep:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: keelson-ai/keelson-action@v1
        with:
          target-url: ${{ vars.AGENT_ENDPOINT }}
          api-key: ${{ secrets.AGENT_API_KEY }}
          tier: deep
          category: permission-boundaries
          fail-on-vuln: true
```
