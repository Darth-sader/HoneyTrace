"""Unit tests: correlation, session tracking, causal graph and incidents."""

from __future__ import annotations

from honeytrace.engine.correlate import SessionTracker, build_causal_graph, events_share_evidence
from honeytrace.engine.incidents import IncidentManager
from honeytrace.engine.normalize import Normalizer
from honeytrace.engine.rules import RuleEngine
from honeytrace.models.events import Event
from honeytrace.models.actors import ActorRef, FileTarget, ProcessRef
from honeytrace.models.incidents import RuleMatch


def _ev(etype="file.open", session="s1", uid=1000, pid=None, decoy=False, source="filesystem"):
    return Event(
        event_type=etype,
        source=source,
        timestamp_utc="2026-10-11T10:00:00.000Z",
        actor=ActorRef(uid=uid, username=f"u{uid}"),
        session_id=session,
        process=ProcessRef(pid=pid, ppid=1, start_time=5.0) if pid else None,
        target=FileTarget(path="/lab/f", is_decoy=decoy, decoy_id="DCY-9" if decoy else None),
    )


def test_session_tracker_lifecycle():
    t = SessionTracker()
    opened = _ev("auth.session_open", session="ssh-7", source="auth")
    opened.actor.auth_method = "ssh-password"
    s = t.observe(opened)
    assert s.state == "opened"
    s2 = t.observe(_ev("auth.session_close", session="ssh-7", source="auth"))
    assert s2.state == "closed"
    assert t.active_sessions() == []


def test_session_tracker_lookup_by_uid():
    t = SessionTracker()
    ev = _ev("auth.session_open", session="ssh-9", source="auth")
    t.observe(ev)
    assert t.lookup(None, uid=1000).session_id == "ssh-9"
    assert t.lookup(None, uid=2000) is None


def test_events_share_evidence_rules():
    a = _ev(session="sA", uid=1000)
    b = _ev(session="sA", uid=1000)
    assert events_share_evidence(a, b)         # same session: hard evidence
    c = _ev(session="sB", uid=1000)            # same uid, no ip/tty: weak
    assert not events_share_evidence(a, c)
    d = _ev(session=None, uid=2000)
    e = _ev(session=None, uid=2000)
    a.actor.source_ip = "10.0.0.9"
    d.actor.source_ip = "10.0.0.9"
    e.actor.source_ip = "10.0.0.9"
    assert events_share_evidence(d, e)         # same uid + same source endpoint


def test_causal_graph_edges_and_inference():
    events = [
        {
            "event_id": "e1", "event_type": "auth.session_open",
            "timestamp_utc": "2026-10-11T10:00:00Z", "source": "auth",
            "session_id": "sX",
        },
        {
            "event_id": "e2", "event_type": "file.open",
            "timestamp_utc": "2026-10-11T10:00:05Z", "source": "filesystem",
            "session_id": "sX", "decoy_id": "DCY-9",
            "process": {"pid": 55, "start_time": 1.0},
        },
        {
            # Different session, same process -> same-process edge.
            "event_id": "e3", "event_type": "file.read",
            "timestamp_utc": "2026-10-11T10:00:09Z", "source": "filesystem",
            "session_id": "sY", "decoy_id": "DCY-9",
            "process": {"pid": 55, "start_time": 1.0},
        },
        {
            # Different session and process, same decoy -> same-decoy edge.
            "event_id": "e4", "event_type": "decoy.token_callback",
            "timestamp_utc": "2026-10-11T10:00:20Z", "source": "canary",
            "session_id": "sZ", "decoy_id": "DCY-9",
        },
        {
            # Nothing shared but ordering -> time-adjacent, explicitly inferred.
            "event_id": "e5", "event_type": "exec.command",
            "timestamp_utc": "2026-10-11T10:00:30Z", "source": "audit",
            "session_id": "sW",
        },
    ]
    g = build_causal_graph(events)
    bases = {e["basis"] for e in g["edges"]}
    assert "same-session" in bases
    assert "same-decoy" in bases
    assert "same-process" in bases
    assert "time-adjacent" in bases
    # Every edge states whether it is inferred; time-adjacency is always inferred.
    assert all(isinstance(e["inferred"], bool) for e in g["edges"])
    assert all(e["inferred"] for e in g["edges"] if e["basis"] == "time-adjacent")


def _match(rid="R-DECOY-001", severity="high", conf=0.8, event_ids=None):
    return RuleMatch(
        rule_id=rid, rule_name="Decoy accessed", severity=severity, confidence=conf,
        fired_at_utc="2026-10-11T10:00:00.000Z",
        contributing_event_ids=event_ids or [],
        threshold={"required": 1, "observed": 1, "window_seconds": 600},
        explanation="test explanation", mitre=["T1083"],
    )


def test_incident_created_and_persisted(settings):
    mgr = IncidentManager(settings.data_dir / "incidents", incident_gap_seconds=900)
    ev = _ev(decoy=True, session="s1")
    touched = mgr.on_matches([_match()], event=ev, sensor_status={"filesystem": "ok"})
    assert len(touched) == 1
    inc = touched[0]
    assert inc.event_ids == [ev.event_id]
    assert inc.severity == "high"
    assert inc.rule_matches[0].rule_id == "R-DECOY-001"
    # Persisted to disk and reloadable.
    from honeytrace.engine.incidents import IncidentManager as IM

    mgr2 = IM(settings.data_dir / "incidents")
    assert mgr2.get(inc.incident_id) is not None


def test_separate_sessions_stay_separate(settings):
    mgr = IncidentManager(settings.data_dir / "incidents")
    e1 = _ev(decoy=True, session="s1")
    e2 = _ev(decoy=True, session="s2")
    m1 = mgr.on_matches([_match()], event=e1)
    m2 = mgr.on_matches([_match()], event=e2)
    assert m1[0].incident_id != m2[0].incident_id


def test_same_session_merges_into_one_incident(settings):
    mgr = IncidentManager(settings.data_dir / "incidents")
    e1 = _ev(decoy=True, session="s1")
    e2 = _ev(decoy=True, session="s1")
    m1 = mgr.on_matches([_match()], event=e1)
    m2 = mgr.on_matches([_match()], event=e2)
    assert m1[0].incident_id == m2[0].incident_id


def test_ack_and_read_flow(settings):
    mgr = IncidentManager(settings.data_dir / "incidents")
    inc = mgr.on_matches([_match()], event=_ev(decoy=True, session="s3"))[0]
    assert mgr.unread_count() == 1
    mgr.mark_read(inc.incident_id)
    assert mgr.unread_count() == 0
    mgr.acknowledge(inc.incident_id, by="operator")
    assert mgr.get(inc.incident_id).status == "acknowledged"
    # Opening a report must NOT resolve the incident.
    assert mgr.get(inc.incident_id).status != "closed"


def test_end_to_end_event_to_incident(settings):
    """Normalizer -> rules -> incident manager on a realistic event flow."""
    n = Normalizer()
    eng = RuleEngine(settings.rules)
    mgr = IncidentManager(settings.data_dir / "incidents")
    raw = {
        "event_type": "file.open",
        "source": "filesystem",
        "session_id": "s9",
        "actor": {"uid": 1001, "username": "labuser"},
        "target": {"path": "/lab/docs/bait.pdf", "is_decoy": True, "decoy_id": "DCY-77"},
    }
    ev = n.normalize(raw)
    matches = eng.on_event(ev)
    assert matches
    touched = mgr.on_matches(matches, event=ev)
    assert touched[0].event_ids == [ev.event_id]
