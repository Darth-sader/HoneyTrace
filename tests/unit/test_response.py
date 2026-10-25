"""Unit tests: response engine gating, dry-run, trusted bypass and rollback.

The firewall itself is mocked (no iptables in test environments); the tests
exercise the GATES and the rollback journal, which is where safety lives.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from honeytrace.engine.response import ArmingState, FirewallManager, ResponseEngine
from honeytrace.models.incidents import ResponseActionRecord, RuleMatch


@pytest.fixture()
def arming(settings):
    return ArmingState(settings.data_dir / "state")


@pytest.fixture()
def engine(settings, arming):
    eng = ResponseEngine(settings, arming)
    # The lab user does not exist on dev machines; pin it for the gates.
    eng._lab_uid = lambda: 1001

    # Stub the firewall so tests never touch a real firewall.
    class FakeFW:
        backend = "iptables"
        applied = []

        def apply_isolation(self, uid, tag):
            rec = ResponseActionRecord(
                action_id="fake", action="isolate", status="applied",
                target=f"uid:{uid}", reason="fake",
                rollback_cmd=f"iptables -D ... {tag}", applied_at_utc="now",
            )
            FakeFW.applied.append(tag)
            return rec

        def remove_rule(self, uid, tag):
            if tag in FakeFW.applied:
                FakeFW.applied.remove(tag)
                return True, "removed"
            return True, "already absent"

    eng.firewall = FakeFW()
    return eng


def _match(policy="isolate", rid="R-EXFIL-011"):
    return RuleMatch(
        rule_id=rid, rule_name="t", severity="critical", confidence=0.8,
        fired_at_utc="2026-10-11T10:00:00.000Z",
        threshold={"required": 1, "observed": 1, "window_seconds": 60},
        explanation="test", response_policy=policy,
    )


def test_disarmed_never_applies_containment(settings, arming, engine):
    arming.disarm()
    rec = engine.evaluate(_match("isolate"), None, {"actor": {"uid": 1001}})
    assert rec.status == "proposed"
    assert "containment not armed" in rec.reason


def test_dry_run_logs_without_changes(settings, arming, engine):
    arming.arm("contain", confirm_containment=True)
    # Config default is dry_run=true.
    rec = engine.evaluate(_match("isolate"), None, {"actor": {"uid": 1001}})
    assert rec.status == "dry_run"
    assert FakeFW_noop(engine)


def FakeFW_noop(engine) -> bool:
    return len(engine.firewall.applied) == 0


def test_armed_contain_applies_scoped_rule(settings, arming, engine):
    arming.arm("contain", confirm_containment=True)
    settings.honeytrace.response.dry_run = False
    rec = engine.evaluate(_match("isolate"), None, {"actor": {"uid": 1001}})
    assert rec.status == "applied"
    # Rollback entry journaled.
    assert engine.rollback_path.exists()


def test_refuses_to_contain_non_lab_uid(settings, arming, engine):
    arming.arm("contain", confirm_containment=True)
    settings.honeytrace.response.dry_run = False
    rec = engine.evaluate(_match("isolate"), None, {"actor": {"uid": 0}})
    assert rec.status == "failed"
    assert "refusing" in rec.reason


def test_trusted_user_bypass(settings, arming, engine):
    settings.honeytrace.response.trusted_users = ["admin"]
    arming.arm("contain", confirm_containment=True)
    settings.honeytrace.response.dry_run = False
    rec = engine.evaluate(_match("isolate"), None, {"actor": {"uid": 0, "username": "admin"}})
    assert "trusted_users" in rec.reason


def test_trusted_network_bypass(settings, arming, engine):
    arming.arm("contain", confirm_containment=True)
    settings.honeytrace.response.dry_run = False
    rec = engine.evaluate(
        _match("isolate"), None, {"actor": {"uid": 1001, "source_ip": "192.168.1.5"}}
    )
    assert "trusted network" in rec.reason


def test_rollback_all_idempotent(settings, arming, engine):
    arming.arm("contain", confirm_containment=True)
    settings.honeytrace.response.dry_run = False
    engine.evaluate(_match("isolate"), None, {"actor": {"uid": 1001}})
    assert engine.firewall.applied
    s1 = engine.rollback_all()
    assert s1["rolled_back"] == 1
    s2 = engine.rollback_all()
    assert s2["rolled_back"] == 0 and s2["already_absent"] >= 1  # idempotent


def test_emergency_off_disables_and_rolls_back(settings, arming, engine):
    arming.arm("contain", confirm_containment=True)
    settings.honeytrace.response.dry_run = False
    engine.evaluate(_match("isolate"), None, {"actor": {"uid": 1001}})
    summary = engine.emergency_off()
    assert summary["rolled_back"] == 1
    assert engine.enabled is False
    assert arming.body["state"] == "disarmed"
    # After emergency off, nothing applies anymore.
    engine.enabled = True
    rec = engine.evaluate(_match("isolate"), None, {"actor": {"uid": 1001}})
    assert rec.status == "proposed"  # containment_armed cleared by disarm


def test_alert_policy_applies_without_containment(settings, arming, engine):
    rec = engine.evaluate(_match("alert", rid="R-DECOY-001"), None, {"actor": {"uid": 1001}})
    assert rec.status == "applied"


def test_firewall_manager_without_iptables_is_safe(settings):
    """On systems without iptables, apply must fail closed, not crash."""
    fw = FirewallManager(backend="iptables")
    fw.backend = "definitely-not-a-binary"
    rec = fw.apply_isolation(12345, "test-tag")
    assert rec.status == "failed"
