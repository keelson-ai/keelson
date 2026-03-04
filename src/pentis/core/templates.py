"""Markdown playbook parser for attack templates."""

from __future__ import annotations

import re
from pathlib import Path

from pentis.core.models import AttackStep, AttackTemplate, Category, EvalCriteria, Severity

ATTACKS_DIR = Path(__file__).resolve().parents[2].parent / "attacks"

CATEGORY_MAP = {
    "goal adherence": Category.GOAL_ADHERENCE,
    "goal-adherence": Category.GOAL_ADHERENCE,
    "tool safety": Category.TOOL_SAFETY,
    "tool-safety": Category.TOOL_SAFETY,
    "memory integrity": Category.MEMORY_INTEGRITY,
    "memory-integrity": Category.MEMORY_INTEGRITY,
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def parse_template(text: str, source_path: str = "") -> AttackTemplate:
    """Parse a single attack playbook markdown into an AttackTemplate."""
    lines = text.split("\n")

    # Parse header: # GA-001: Direct Instruction Override
    header_match = re.match(r"^#\s+(\S+):\s+(.+)$", lines[0].strip())
    if not header_match:
        raise ValueError(f"Invalid header: {lines[0]}")
    attack_id = header_match.group(1)
    attack_name = header_match.group(2).strip()

    # Parse metadata line: **Severity**: High | **Category**: ... | **OWASP**: ...
    severity = Severity.MEDIUM
    category = Category.GOAL_ADHERENCE
    owasp = ""
    for line in lines[1:10]:
        if "**Severity**" in line and "**Category**" in line:
            sev_match = re.search(r"\*\*Severity\*\*:\s*(\w+)", line)
            cat_match = re.search(r"\*\*Category\*\*:\s*([^|]+)", line)
            owasp_match = re.search(r"\*\*OWASP\*\*:\s*(.+)$", line)
            if sev_match:
                severity = SEVERITY_MAP.get(sev_match.group(1).lower(), Severity.MEDIUM)
            if cat_match:
                cat_text = cat_match.group(1).strip().rstrip("|").strip()
                category = CATEGORY_MAP.get(cat_text.lower(), Category.GOAL_ADHERENCE)
            if owasp_match:
                owasp = owasp_match.group(1).strip()
            break

    # Extract sections by ## headers
    sections: dict[str, str] = {}
    current_section = ""
    section_lines: list[str] = []
    for line in lines:
        h2_match = re.match(r"^##\s+(.+)$", line)
        if h2_match:
            if current_section:
                sections[current_section] = "\n".join(section_lines).strip()
            current_section = h2_match.group(1).strip()
            section_lines = []
        else:
            section_lines.append(line)
    if current_section:
        sections[current_section] = "\n".join(section_lines).strip()

    # Parse objective
    objective = sections.get("Objective", "")

    # Parse attack steps
    steps = _parse_steps(sections.get("Attack Steps", ""))

    # Parse evaluation criteria
    eval_criteria = _parse_eval(sections.get("Evaluation", ""))

    return AttackTemplate(
        id=attack_id,
        name=attack_name,
        severity=severity,
        category=category,
        owasp=owasp,
        objective=objective,
        steps=steps,
        eval_criteria=eval_criteria,
        source_path=source_path,
    )


def _parse_steps(text: str) -> list[AttackStep]:
    """Parse ### Step N sections and extract blockquoted prompts."""
    steps: list[AttackStep] = []
    step_blocks = re.split(r"###\s+Step\s+(\d+)", text)
    # step_blocks: ['', '1', 'content', '2', 'content', ...]
    i = 1
    while i < len(step_blocks) - 1:
        step_num = int(step_blocks[i])
        content = step_blocks[i + 1]
        is_followup = "follow-up" in content.lower() or "followup" in content.lower()
        prompt = _extract_blockquote(content)
        steps.append(AttackStep(index=step_num, prompt=prompt, is_followup=is_followup))
        i += 2
    return steps


def _extract_blockquote(text: str) -> str:
    """Extract blockquoted content (lines starting with >) from text."""
    lines = text.split("\n")
    quote_lines: list[str] = []
    in_quote = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(">"):
            in_quote = True
            # Remove the leading > and optional space
            content = stripped[1:]
            if content.startswith(" "):
                content = content[1:]
            quote_lines.append(content)
        elif in_quote and stripped == "":
            # Blank line inside a multi-line blockquote — keep it
            quote_lines.append("")
        elif in_quote:
            # Non-quote line after quote started — end of blockquote
            break
    # Strip trailing blank lines
    while quote_lines and quote_lines[-1] == "":
        quote_lines.pop()
    return "\n".join(quote_lines)


def _parse_eval(text: str) -> EvalCriteria:
    """Parse evaluation criteria sections."""
    criteria = EvalCriteria()
    current: list[str] | None = None
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("**Vulnerable if**"):
            current = criteria.vulnerable_if
        elif stripped.startswith("**Safe if**"):
            current = criteria.safe_if
        elif stripped.startswith("**Inconclusive if**"):
            current = criteria.inconclusive_if
        elif stripped.startswith("- ") and current is not None:
            current.append(stripped[2:])
    return criteria


def load_template(path: Path) -> AttackTemplate:
    """Load and parse a single attack template from a file."""
    text = path.read_text()
    return parse_template(text, source_path=str(path))


def load_all_templates(
    attacks_dir: Path | None = None, category: str | None = None
) -> list[AttackTemplate]:
    """Load all attack templates from the attacks directory."""
    root = attacks_dir or ATTACKS_DIR
    if category:
        root = root / category
    templates = []
    for path in sorted(root.rglob("*.md")):
        templates.append(load_template(path))
    return templates
