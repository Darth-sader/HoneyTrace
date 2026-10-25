"""Unit tests: models, canonical JSON, event integrity."""

from __future__ import annotations

import json

from honeytrace.models.actors import ActorRef, FileTarget, ProcessRef
from honeytrace.models.events import Event, canonical_json, utc_now_iso
from honeytrace.models.incidents import EvidenceCoverage, Incident, RuleMatch


def test_event_defaults_are_unique_and_absent_not_null():
    a = Event(event_type="file.open", source="filesystem")
    b = Event(event_type="file.open", source="filesystem")
    assert a.event_id != b.event_id
    d = a.to_dict()
    assert "decoy_id" not in d          # optional fields are ABSENT, not null
    assert "session_id" not in d
    assert d["details"] == {} or "details" not in d


def test_canonical_json_is_stable():
    ev = Event(
        event_type="decoy.token_callback",
        source="canary",
        actor=ActorRef(uid=1000, username="lab", source_ip="203.0.113.5"),
    )
    j1 = canonical_json(ev.to_dict())
    j2 = canonical_json(ev.to_dict())
    assert j1 == j2
    # Sorted keys: canonical form must be byte-identical after a round-trip.
    parsed = json.loads(j1)
    assert canonical_json(parsed) == j1


def test_canonical_json_rejects_nan():
    import pytest

    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_process_ref_pid_reuse_fields():
    p = ProcessRef(pid=42, ppid=1, start_time=1234.5, exe="/usr/bin/cat")
    assert p.model_dump(mode="json")["start_time"] == 1234.5


def test_filetarget_decoy_fields():
    t = FileTarget(path="/lab/bait.pdf", is_decoy=True, decoy_id="DCY-1")
    assert t.is_decoy and t.decoy_id == "DCY-1"


def test_rule_match_threshold_and_mitre():
    m = RuleMatch(
        rule_id="R-DECOY-001", rule_name="Decoy accessed", severity="high",
        confidence=0.8, fired_at_utc=utc_now_iso(),
        contributing_event_ids=["a", "b"],
        threshold={"required": 1, "observed": 1, "window_seconds": 600},
        explanation="test", mitre=["T1083"],
    )
    d = m.model_dump(mode="json")
    assert d["threshold"]["observed"] == 1
    assert "T1083" in d["mitre"]


def test_evidence_coverage_score():
    c = EvidenceCoverage(
        expected_sensors=["filesystem", "audit", "auth"],
        contributing_sensors=["filesystem"],
    )
    assert abs(c.score - 1 / 3) < 1e-9
    assert c.score < 1.0  # coverage, never completeness


def test_incident_merge_severity_only_increases():
    inc = Incident(
        incident_id="INC-TEST-1", created_at_utc=utc_now_iso(),
        updated_at_utc=utc_now_iso(), severity="low",
    )
    inc.merge_severity("high")
    inc.merge_severity("low")
    assert inc.severity == "high"


def test_incident_serialization_roundtrip():
    inc = Incident(
        incident_id="INC-TEST-2", created_at_utc=utc_now_iso(),
        updated_at_utc=utc_now_iso(), severity="high", confidence=0.7,
        event_ids=["e1", "e2"], event_count=2,
    )
    body = inc.to_dict()
    clone = Incident.model_validate(body)
    assert clone.incident_id == inc.incident_id
    assert clone.event_ids == ["e1", "e2"]
