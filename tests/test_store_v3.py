"""Tests for Phase 3 store extensions (cache, regression alerts, attack chains)."""

import pytest
from pathlib import Path

from pentis.core.models import (
    AttackChain,
    AttackStep,
    Category,
    RegressionAlert,
    Severity,
    Verdict,
)
from pentis.state.store import Store


@pytest.fixture
def store(tmp_path):
    db_path = tmp_path / "test.db"
    s = Store(db_path=db_path)
    yield s
    s.close()


class TestResponseCachePersistence:
    def test_save_and_get_cache_entry(self, store):
        store.save_cache_entry(
            cache_key="abc123",
            messages=[{"role": "user", "content": "test"}],
            model="gpt-4",
            response_text="Hello!",
            response_time_ms=150,
        )
        entry = store.get_cache_entry("abc123")
        assert entry is not None
        assert entry["response_text"] == "Hello!"
        assert entry["model"] == "gpt-4"
        assert entry["response_time_ms"] == 150

    def test_cache_miss(self, store):
        entry = store.get_cache_entry("nonexistent")
        assert entry is None

    def test_hit_count_increments(self, store):
        store.save_cache_entry(
            cache_key="key1",
            messages=[],
            model="gpt-4",
            response_text="resp",
            response_time_ms=100,
        )
        store.get_cache_entry("key1")  # hit_count becomes 1
        store.get_cache_entry("key1")  # hit_count becomes 2
        # Read the raw row to check final count
        row = store._conn.execute(
            "SELECT hit_count FROM response_cache WHERE cache_key = ?", ("key1",)
        ).fetchone()
        assert row["hit_count"] == 2


class TestRegressionAlertsPersistence:
    def test_save_and_list_alerts(self, store):
        alerts = [
            RegressionAlert(
                template_id="GA-001",
                alert_severity="critical",
                change_type="regression",
                description="SAFE → VULNERABLE",
            ),
            RegressionAlert(
                template_id="GA-002",
                alert_severity="medium",
                change_type="regression",
                description="INCONCLUSIVE → VULNERABLE",
            ),
        ]
        store.save_regression_alerts("scan-a", "scan-b", alerts)
        rows = store.list_regression_alerts()
        assert len(rows) == 2
        assert rows[0]["template_id"] in ("GA-001", "GA-002")

    def test_acknowledge_alert(self, store):
        alerts = [
            RegressionAlert(
                template_id="GA-001",
                alert_severity="high",
                change_type="regression",
                description="test",
            ),
        ]
        store.save_regression_alerts("scan-a", "scan-b", alerts)
        rows = store.list_regression_alerts()
        alert_id = rows[0]["id"]
        assert rows[0]["acknowledged"] == 0

        store.acknowledge_alert(alert_id)
        rows = store.list_regression_alerts()
        assert rows[0]["acknowledged"] == 1


class TestAttackChainPersistence:
    def test_save_and_get_chain(self, store):
        chain = AttackChain(
            chain_id="chain-001",
            name="Data Exfiltration",
            capabilities=["file_access", "web_access"],
            steps=[
                AttackStep(index=1, prompt="Read files"),
                AttackStep(index=2, prompt="Send data", is_followup=True),
            ],
            severity=Severity.CRITICAL,
            category=Category.AGENTIC_SECURITY,
            owasp="LLM08",
        )
        store.save_attack_chain(chain, profile_id=None)
        loaded = store.get_attack_chain("chain-001")
        assert loaded is not None
        assert loaded.name == "Data Exfiltration"
        assert loaded.capabilities == ["file_access", "web_access"]
        assert len(loaded.steps) == 2
        assert loaded.steps[0].prompt == "Read files"
        assert loaded.steps[1].is_followup is True
        assert loaded.severity == Severity.CRITICAL

    def test_get_nonexistent_chain(self, store):
        assert store.get_attack_chain("nonexistent") is None

    def test_list_chains(self, store):
        # Insert a profile first to satisfy FK constraint
        from pentis.core.models import AgentProfile, AgentCapability
        profile = AgentProfile(
            profile_id="profile-1",
            target_url="https://example.com",
            capabilities=[AgentCapability(name="file_access", detected=True, probe_prompt="test")],
        )
        store.save_agent_profile(profile)

        for i in range(3):
            chain = AttackChain(
                chain_id=f"chain-{i:03d}",
                name=f"Chain {i}",
                capabilities=["file_access"],
                steps=[AttackStep(index=1, prompt="test")],
                severity=Severity.HIGH,
                category=Category.AGENTIC_SECURITY,
                owasp="LLM08",
            )
            store.save_attack_chain(chain, profile_id="profile-1")

        all_chains = store.list_attack_chains()
        assert len(all_chains) == 3

        profile_chains = store.list_attack_chains(profile_id="profile-1")
        assert len(profile_chains) == 3

    def test_upsert_chain(self, store):
        chain = AttackChain(
            chain_id="chain-001",
            name="Original",
            capabilities=["file_access"],
            steps=[AttackStep(index=1, prompt="test")],
            severity=Severity.HIGH,
            category=Category.AGENTIC_SECURITY,
            owasp="LLM08",
        )
        store.save_attack_chain(chain)

        chain.name = "Updated"
        store.save_attack_chain(chain)

        loaded = store.get_attack_chain("chain-001")
        assert loaded.name == "Updated"
