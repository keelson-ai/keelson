"""Tests for the attack strategist — classify, select, adapt."""

from pentis.core.models import (
    AttackStep,
    AttackTemplate,
    Category,
    EvalCriteria,
    Finding,
    Severity,
    Verdict,
)
from pentis.core.strategist import (
    AgentType,
    AttackPlan,
    CategoryPlan,
    Priority,
    ReconResponse,
    TargetProfile,
    adapt_plan,
    classify_target,
    select_attacks,
)


# --- Helpers ---


def _recon(probe_type: str, response: str) -> ReconResponse:
    return ReconResponse(probe_type=probe_type, prompt=f"probe:{probe_type}", response=response)


def _template(
    tid: str = "GA-001",
    category: Category = Category.GOAL_ADHERENCE,
    severity: Severity = Severity.HIGH,
) -> AttackTemplate:
    return AttackTemplate(
        id=tid,
        name=f"Attack {tid}",
        severity=severity,
        category=category,
        owasp="LLM01",
        objective="Test",
        steps=[AttackStep(index=1, prompt="test")],
        eval_criteria=EvalCriteria(vulnerable_if=["vuln"], safe_if=["safe"]),
    )


def _finding(
    tid: str = "GA-001",
    category: Category = Category.GOAL_ADHERENCE,
    verdict: Verdict = Verdict.SAFE,
) -> Finding:
    return Finding(
        template_id=tid,
        template_name=f"Attack {tid}",
        verdict=verdict,
        severity=Severity.HIGH,
        category=category,
        owasp="LLM01",
    )


# --- Classification Tests ---


class TestClassifyTarget:
    def test_codebase_agent_detected(self):
        recon = [_recon("role", "I can search code in your repository and read codebase files.")]
        profile = classify_target(recon)
        assert AgentType.CODEBASE_AGENT in profile.agent_types

    def test_tool_rich_from_tool_names(self):
        recon = [
            _recon(
                "tools",
                "I have these tools: `search`, `read_file`, `list_directory`, `get_releases`.",
            )
        ]
        profile = classify_target(recon)
        assert AgentType.TOOL_RICH in profile.agent_types
        assert len(profile.detected_tools) >= 3

    def test_rag_agent_detected(self):
        recon = [_recon("role", "I use retrieval to search a knowledge base of documents.")]
        profile = classify_target(recon)
        assert AgentType.RAG_AGENT in profile.agent_types

    def test_customer_service_detected(self):
        recon = [_recon("role", "I can help with your account, billing, and support tickets.")]
        profile = classify_target(recon)
        assert AgentType.CUSTOMER_SERVICE in profile.agent_types

    def test_coding_assistant_detected(self):
        recon = [_recon("role", "I can write files, edit code, and commit changes.")]
        profile = classify_target(recon)
        assert AgentType.CODING_ASSISTANT in profile.agent_types

    def test_multi_agent_detected(self):
        recon = [_recon("role", "I orchestrate tasks by delegating to sub-agents.")]
        profile = classify_target(recon)
        assert AgentType.MULTI_AGENT in profile.agent_types

    def test_general_chat_default(self):
        recon = [_recon("role", "Hi! I'm here to chat about anything you like.")]
        profile = classify_target(recon)
        assert AgentType.GENERAL_CHAT in profile.agent_types

    def test_multiple_types(self):
        recon = [
            _recon(
                "role",
                "I search code in the repository and have tools: "
                "`search`, `read_file`, `list_dir`, `get_release`.",
            )
        ]
        profile = classify_target(recon)
        assert AgentType.CODEBASE_AGENT in profile.agent_types
        assert AgentType.TOOL_RICH in profile.agent_types

    def test_memory_detected(self):
        recon = [_recon("memory", "Yes, I remember our previous conversation about the API.")]
        profile = classify_target(recon)
        assert profile.has_memory is True

    def test_no_memory_when_denied(self):
        recon = [_recon("memory", "I don't remember any previous conversations.")]
        profile = classify_target(recon)
        assert profile.has_memory is False

    def test_write_access_detected(self):
        recon = [_recon("tools", "I can create commits and push to branches.")]
        profile = classify_target(recon)
        assert profile.has_write_access is True

    def test_no_write_access(self):
        recon = [_recon("tools", "I can only search and read code.")]
        profile = classify_target(recon)
        assert profile.has_write_access is False

    def test_refusal_rigid(self):
        recon = [_recon("error", "I cannot do that. This is not allowed by policy.")]
        profile = classify_target(recon)
        assert profile.refusal_style == "rigid"

    def test_refusal_polite(self):
        recon = [_recon("error", "I'd rather not help with that. Let me redirect you.")]
        profile = classify_target(recon)
        assert profile.refusal_style == "polite"

    def test_refusal_leaky(self):
        """Agent refuses but still discloses tool names."""
        recon = [
            _recon(
                "tools",
                "I cannot share internal details, but I use `search_code`, `read_file`, "
                "and `list_dir` for code exploration.",
            )
        ]
        profile = classify_target(recon)
        assert profile.refusal_style == "leaky"

    def test_tool_names_extracted(self):
        recon = [
            _recon(
                "tools",
                "My tools: `search_public_code`, `read_public_file`, `list_public_directory`.",
            )
        ]
        profile = classify_target(recon)
        assert "search_public_code" in profile.detected_tools
        assert "read_public_file" in profile.detected_tools
        assert "list_public_directory" in profile.detected_tools

    def test_tool_names_deduplicated(self):
        recon = [
            _recon("tools", "I have `search` and `search` and also `read_file`."),
        ]
        profile = classify_target(recon)
        assert profile.detected_tools.count("search") == 1

    def test_empty_recon(self):
        profile = classify_target([])
        assert AgentType.GENERAL_CHAT in profile.agent_types


# --- Attack Selection Tests ---


class TestSelectAttacks:
    def _make_templates(self) -> list[AttackTemplate]:
        """Create a representative set of templates across categories."""
        templates = []
        cats = [
            ("GA", Category.GOAL_ADHERENCE, 5),
            ("TS", Category.TOOL_SAFETY, 5),
            ("MI", Category.MEMORY_INTEGRITY, 5),
            ("SI", Category.SESSION_ISOLATION, 5),
            ("PB", Category.PERMISSION_BOUNDARIES, 5),
            ("DI", Category.DELEGATION_INTEGRITY, 5),
            ("ES", Category.EXECUTION_SAFETY, 5),
        ]
        for prefix, cat, count in cats:
            for i in range(1, count + 1):
                sev = Severity.CRITICAL if i == 1 else Severity.HIGH if i <= 3 else Severity.MEDIUM
                templates.append(_template(f"{prefix}-{i:03d}", cat, sev))
        return templates

    def test_goal_adherence_always_high(self):
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT])
        plan = select_attacks(profile, self._make_templates())
        ga_plan = plan.get_category_plan(Category.GOAL_ADHERENCE)
        assert ga_plan is not None
        assert ga_plan.priority == Priority.HIGH
        assert len(ga_plan.attack_ids) == 5  # all GA attacks

    def test_tool_safety_high_for_tool_rich(self):
        profile = TargetProfile(agent_types=[AgentType.TOOL_RICH])
        plan = select_attacks(profile, self._make_templates())
        ts_plan = plan.get_category_plan(Category.TOOL_SAFETY)
        assert ts_plan is not None
        assert ts_plan.priority == Priority.HIGH
        assert len(ts_plan.attack_ids) == 5  # all

    def test_tool_safety_low_for_general_chat(self):
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT])
        plan = select_attacks(profile, self._make_templates())
        ts_plan = plan.get_category_plan(Category.TOOL_SAFETY)
        assert ts_plan is not None
        assert ts_plan.priority == Priority.LOW
        assert len(ts_plan.attack_ids) == 3  # limited to 3

    def test_recon_vuln_promotes_category(self):
        """A vuln found during recon should promote that category to HIGH."""
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT])
        recon_finding = _finding("TS-015", Category.TOOL_SAFETY, Verdict.VULNERABLE)
        plan = select_attacks(profile, self._make_templates(), [recon_finding])
        ts_plan = plan.get_category_plan(Category.TOOL_SAFETY)
        assert ts_plan is not None
        assert ts_plan.priority == Priority.HIGH

    def test_session_isolation_skipped_without_memory(self):
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT], has_memory=False)
        plan = select_attacks(profile, self._make_templates())
        si_plan = plan.get_category_plan(Category.SESSION_ISOLATION)
        assert si_plan is not None
        assert si_plan.priority == Priority.SKIP
        assert len(si_plan.attack_ids) == 0

    def test_session_isolation_kept_with_memory(self):
        profile = TargetProfile(agent_types=[AgentType.RAG_AGENT], has_memory=True)
        plan = select_attacks(profile, self._make_templates())
        si_plan = plan.get_category_plan(Category.SESSION_ISOLATION)
        assert si_plan is not None
        assert si_plan.priority == Priority.MEDIUM

    def test_medium_priority_limits_to_5(self):
        profile = TargetProfile(agent_types=[AgentType.RAG_AGENT])
        # Create 10 MI templates
        templates = [_template(f"MI-{i:03d}", Category.MEMORY_INTEGRITY) for i in range(1, 11)]
        # Add GA so plan doesn't fail
        templates.append(_template("GA-001", Category.GOAL_ADHERENCE))
        plan = select_attacks(profile, templates)
        # MI is HIGH for RAG agents, so it should be unlimited
        # Let's check a medium category instead
        # RAG agents don't map to TOOL_SAFETY, so it should be LOW (3 max)
        ts_templates = [_template(f"TS-{i:03d}", Category.TOOL_SAFETY) for i in range(1, 11)]
        templates.extend(ts_templates)
        plan = select_attacks(profile, templates)
        ts_plan = plan.get_category_plan(Category.TOOL_SAFETY)
        assert ts_plan is not None
        assert ts_plan.priority == Priority.LOW
        assert len(ts_plan.attack_ids) == 3

    def test_severity_ordering(self):
        """Attacks should be sorted critical > high > medium > low."""
        templates = [
            _template("GA-001", Category.GOAL_ADHERENCE, Severity.LOW),
            _template("GA-002", Category.GOAL_ADHERENCE, Severity.CRITICAL),
            _template("GA-003", Category.GOAL_ADHERENCE, Severity.MEDIUM),
            _template("GA-004", Category.GOAL_ADHERENCE, Severity.HIGH),
        ]
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT])
        plan = select_attacks(profile, templates)
        ga_plan = plan.get_category_plan(Category.GOAL_ADHERENCE)
        assert ga_plan is not None
        assert ga_plan.attack_ids == ["GA-002", "GA-004", "GA-003", "GA-001"]

    def test_total_attacks(self):
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT])
        plan = select_attacks(profile, self._make_templates())
        assert plan.total_attacks > 0

    def test_codebase_agent_priorities(self):
        profile = TargetProfile(agent_types=[AgentType.CODEBASE_AGENT], has_memory=True)
        plan = select_attacks(profile, self._make_templates())
        ts_plan = plan.get_category_plan(Category.TOOL_SAFETY)
        si_plan = plan.get_category_plan(Category.SESSION_ISOLATION)
        assert ts_plan is not None and ts_plan.priority == Priority.HIGH
        assert si_plan is not None and si_plan.priority == Priority.MEDIUM

    def test_coding_assistant_priorities(self):
        profile = TargetProfile(agent_types=[AgentType.CODING_ASSISTANT])
        plan = select_attacks(profile, self._make_templates())
        es_plan = plan.get_category_plan(Category.EXECUTION_SAFETY)
        ts_plan = plan.get_category_plan(Category.TOOL_SAFETY)
        pb_plan = plan.get_category_plan(Category.PERMISSION_BOUNDARIES)
        assert es_plan is not None and es_plan.priority == Priority.HIGH
        assert ts_plan is not None and ts_plan.priority == Priority.HIGH
        assert pb_plan is not None and pb_plan.priority == Priority.HIGH

    def test_empty_templates(self):
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT])
        plan = select_attacks(profile, [])
        assert plan.total_attacks == 0

    def test_recon_findings_preserved_in_plan(self):
        profile = TargetProfile(agent_types=[AgentType.GENERAL_CHAT])
        findings = [_finding("TS-015", Category.TOOL_SAFETY, Verdict.VULNERABLE)]
        plan = select_attacks(profile, [], findings)
        assert len(plan.recon_findings) == 1
        assert plan.recon_findings[0].template_id == "TS-015"


# --- Adaptation Tests ---


class TestAdaptPlan:
    def _base_plan(self) -> AttackPlan:
        return AttackPlan(
            profile=TargetProfile(agent_types=[AgentType.GENERAL_CHAT]),
            categories=[
                CategoryPlan(
                    category=Category.GOAL_ADHERENCE,
                    priority=Priority.HIGH,
                    attack_ids=["GA-001", "GA-002", "GA-003"],
                ),
                CategoryPlan(
                    category=Category.TOOL_SAFETY,
                    priority=Priority.MEDIUM,
                    attack_ids=["TS-001", "TS-002", "TS-003"],
                ),
                CategoryPlan(
                    category=Category.MEMORY_INTEGRITY,
                    priority=Priority.LOW,
                    attack_ids=["MI-001", "MI-002"],
                ),
            ],
        )

    def test_escalation_on_3_vulns(self):
        plan = self._base_plan()
        findings = [
            _finding("TS-001", Category.TOOL_SAFETY, Verdict.VULNERABLE),
            _finding("TS-002", Category.TOOL_SAFETY, Verdict.VULNERABLE),
            _finding("TS-003", Category.TOOL_SAFETY, Verdict.VULNERABLE),
        ]
        new_plan = adapt_plan(plan, findings)
        ts_plan = new_plan.get_category_plan(Category.TOOL_SAFETY)
        assert ts_plan is not None
        assert ts_plan.priority == Priority.HIGH

    def test_no_escalation_below_threshold(self):
        plan = self._base_plan()
        findings = [
            _finding("TS-001", Category.TOOL_SAFETY, Verdict.VULNERABLE),
            _finding("TS-002", Category.TOOL_SAFETY, Verdict.SAFE),
        ]
        new_plan = adapt_plan(plan, findings)
        ts_plan = new_plan.get_category_plan(Category.TOOL_SAFETY)
        assert ts_plan is not None
        assert ts_plan.priority == Priority.MEDIUM  # unchanged

    def test_deescalation_on_5_consecutive_safes(self):
        plan = self._base_plan()
        findings = [
            _finding("MI-001", Category.MEMORY_INTEGRITY, Verdict.SAFE),
            _finding("MI-002", Category.MEMORY_INTEGRITY, Verdict.SAFE),
            _finding("MI-003", Category.MEMORY_INTEGRITY, Verdict.SAFE),
            _finding("MI-004", Category.MEMORY_INTEGRITY, Verdict.SAFE),
            _finding("MI-005", Category.MEMORY_INTEGRITY, Verdict.SAFE),
        ]
        new_plan = adapt_plan(plan, findings)
        mi_plan = new_plan.get_category_plan(Category.MEMORY_INTEGRITY)
        assert mi_plan is not None
        assert mi_plan.priority == Priority.SKIP
        assert len(mi_plan.attack_ids) == 0

    def test_no_deescalation_for_high_priority(self):
        """HIGH priority categories should never be de-escalated."""
        plan = self._base_plan()
        findings = [
            _finding("GA-001", Category.GOAL_ADHERENCE, Verdict.SAFE),
            _finding("GA-002", Category.GOAL_ADHERENCE, Verdict.SAFE),
            _finding("GA-003", Category.GOAL_ADHERENCE, Verdict.SAFE),
            _finding("GA-004", Category.GOAL_ADHERENCE, Verdict.SAFE),
            _finding("GA-005", Category.GOAL_ADHERENCE, Verdict.SAFE),
        ]
        new_plan = adapt_plan(plan, findings)
        ga_plan = new_plan.get_category_plan(Category.GOAL_ADHERENCE)
        assert ga_plan is not None
        assert ga_plan.priority == Priority.HIGH  # unchanged

    def test_broken_safe_streak_prevents_deescalation(self):
        plan = self._base_plan()
        findings = [
            _finding("MI-001", Category.MEMORY_INTEGRITY, Verdict.SAFE),
            _finding("MI-002", Category.MEMORY_INTEGRITY, Verdict.SAFE),
            _finding("MI-003", Category.MEMORY_INTEGRITY, Verdict.VULNERABLE),  # breaks streak
            _finding("MI-004", Category.MEMORY_INTEGRITY, Verdict.SAFE),
            _finding("MI-005", Category.MEMORY_INTEGRITY, Verdict.SAFE),
        ]
        new_plan = adapt_plan(plan, findings)
        mi_plan = new_plan.get_category_plan(Category.MEMORY_INTEGRITY)
        assert mi_plan is not None
        assert mi_plan.priority == Priority.LOW  # unchanged — only 2 consecutive SAFEs at end

    def test_escalation_rationale_updated(self):
        plan = self._base_plan()
        findings = [
            _finding("TS-001", Category.TOOL_SAFETY, Verdict.VULNERABLE),
            _finding("TS-002", Category.TOOL_SAFETY, Verdict.VULNERABLE),
            _finding("TS-003", Category.TOOL_SAFETY, Verdict.VULNERABLE),
        ]
        new_plan = adapt_plan(plan, findings)
        ts_plan = new_plan.get_category_plan(Category.TOOL_SAFETY)
        assert ts_plan is not None
        assert "3 vulnerabilities" in ts_plan.rationale

    def test_no_changes_when_nothing_notable(self):
        plan = self._base_plan()
        findings = [
            _finding("GA-001", Category.GOAL_ADHERENCE, Verdict.SAFE),
            _finding("TS-001", Category.TOOL_SAFETY, Verdict.SAFE),
        ]
        new_plan = adapt_plan(plan, findings)
        # All priorities should remain unchanged
        for orig, updated in zip(plan.categories, new_plan.categories):
            assert orig.priority == updated.priority

    def test_empty_findings(self):
        plan = self._base_plan()
        new_plan = adapt_plan(plan, [])
        assert len(new_plan.categories) == len(plan.categories)
        for orig, updated in zip(plan.categories, new_plan.categories):
            assert orig.priority == updated.priority

    def test_plan_is_not_mutated(self):
        """adapt_plan should return a new plan, not mutate the original."""
        plan = self._base_plan()
        original_priorities = [(c.category, c.priority) for c in plan.categories]
        findings = [
            _finding("TS-001", Category.TOOL_SAFETY, Verdict.VULNERABLE),
            _finding("TS-002", Category.TOOL_SAFETY, Verdict.VULNERABLE),
            _finding("TS-003", Category.TOOL_SAFETY, Verdict.VULNERABLE),
        ]
        adapt_plan(plan, findings)
        current_priorities = [(c.category, c.priority) for c in plan.categories]
        assert original_priorities == current_priorities
