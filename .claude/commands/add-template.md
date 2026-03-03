# Add Template Command

Create a new YAML attack template for Pentis.

## Usage
```
/add-template <behavior> <id>
```

## Behavior

1. Validate the behavior (goal_adherence, tool_safety, memory_integrity)
2. Validate the ID format (XX-NNN)
3. Create the YAML file in `src/pentis/attacks/<behavior>/`
4. Follow the template schema in `src/pentis/core/template_schema.py`
5. Validate the new template loads correctly

## Template Structure
```yaml
id: "GA-011"
name: "Template Name"
behavior: "goal_adherence"
severity: "high"
description: "What this template tests"
owasp_id: "LLM01"
steps:
  - role: "user"
    content: "Attack prompt here"
indicators:
  - type: "word"
    value: "INDICATOR"
    weight: 3.0
metadata:
  author: "pentis-team"
  version: "1.0"
```

## Implementation

The template arguments are: $ARGUMENTS
