"""Unit tests: reports - timeline, profile, HTML escaping of attacker strings."""

from __future__ import annotations

import json

from honeytrace.evidence.journal import JournalWriter
from honeytrace.engine.incidents import IncidentManager
from honeytrace.engine.rules import RuleEngine
from honeytrace.models.actors import ActorRef, FileTarget, ProcessRef
from honeytrace.models.events import Event
from honeytrace.reports.dashboard import ReportRenderer
from honeytrace.reports.profile import ProfileBuilder
from honeytrace.reports.timeline import TimelineBuilder

ATTACKER_FILENAME = '<script>alert("pwned")</script>/../../etc/passwd'


def _seed_journal(settings, decoy_path=None):
    """Write a small but complete incident into the evidence journal."""
    writer = JournalWriter(settings.data_dir / "events", key_path=settings.data_dir / "state" / "checkpoint.key")
    writer.start()
    n = _norm()
    eng = RuleEngine(settings.rules)
    mgr = IncidentManager(settings.data_dir / "incidents")
    incident = None
    for raw in _raw_events(ATTACKER_FILENAME):
        ev = n.normalize(raw)
        assert ev is not None
        writer.append(ev.to_dict())
        matches = eng.on_event(ev)
        if matches:
            touched = mgr.on_matches(matches, event=ev, sensor_status={"filesystem": "ok", "audit": "unavailable"})
            incident = touched[0]
    writer.close()
    return incident


def _norm():
    from honeytrace.engine.normalize import Normalizer

    return Normalizer()


def _raw_events(evil_path):
    return [
        {
            "event_type": "auth.session_open", "source": "auth",
            "timestamp": "2026-10-11T14:00:00.000Z",
            "session_id": "sess-77",
            "actor": {"uid": 1001, "username": "labuser", "source_ip": "203.0.113.44",
                      "auth_method": "ssh-password", "attribution": "observed"},
        },
        {
            "event_type": "file.open", "source": "filesystem", "session_id": "sess-77",
            "timestamp": "2026-10-11T14:00:05.000Z",
            "actor": {"uid": 1001, "username": "labuser"},
            "process": {"pid": 4242, "ppid": 400, "start_time": 5.0, "exe": "/usr/bin/cat",
                        "ancestry": [["400", "/usr/bin/bash"]]},
            "target": {"path": f"{evil_path}/bait.pdf", "is_decoy": True, "decoy_id": "DCY-EVIL"},
            "decoy_id": "DCY-EVIL",
        },
        {
            "event_type": "net.connection", "source": "network", "session_id": "sess-77",
            "timestamp": "2026-10-11T14:00:09.000Z",
            "actor": {"uid": 1001, "username": "labuser"},
            "network": {"remote_addr": "198.51.100.66", "remote_port": 4444,
                        "direction": "outbound", "owner_pid": 4242, "ownership": "observed"},
            "details": {"allowlisted": False, "direction": "outbound"},
        },
    ]


def test_timeline_build_and_late_arrival(settings):
    incident = _seed_journal(settings)
    assert incident is not None
    builder = TimelineBuilder(settings, IncidentManager(settings.data_dir / "incidents"))
    timeline = builder.build(incident=incident)
    assert timeline["event_count"] >= 3
    assert timeline["events"][0]["event_type"] == "auth.session_open"  # chronological
    assert any(c["decoy_id"] == "DCY-EVIL" for c in timeline["events"])
    assert timeline["gaps"]["coverage"] is not None


def test_timeline_filter(settings):
    _seed_journal(settings)
    builder = TimelineBuilder(settings)
    t = builder.build(event_filter={"event_type": "net.connection"})
    assert t["event_count"] == 1
    t2 = builder.build(event_filter={"source": "auth"})
    assert all(c["source"] == "auth" for c in t2["events"])


def test_profile_separates_observation_from_enrichment(settings):
    incident = _seed_journal(settings)
    profile = ProfileBuilder(settings).build(incident)
    assert profile["actor_id"].startswith("actor:")
    assert "human" in profile["identity_context"]["caveat"].lower()
    assert profile["decoy_interest"]["decoys_touched"]
    assert profile["evidence_map"]["direct_observations"]
    # Alternative explanations must always be offered.
    assert profile["behavior"]["alternative_explanations"]


def test_html_escapes_attacker_strings(settings):
    """Attacker-controlled filenames must never become executable markup."""
    incident = _seed_journal(settings)
    renderer = ReportRenderer(settings, IncidentManager(settings.data_dir / "incidents"))
    paths = renderer.render_all(incident_ids=[incident.incident_id])
    assert len(paths) >= 4  # incident centre, incident detail, timeline, profile
    for p in paths:
        html = p.read_text(encoding="utf-8")
        assert "<script>alert" not in html, f"{p.name} renders raw attacker markup"
    # The timeline and profile pages DO embed the attacker path - they must
    # show it escaped, not dropped.
    for p in paths:
        if p.name.startswith(("timeline", "profile")):
            html = p.read_text(encoding="utf-8")
            assert "&lt;script&gt;" in html, f"{p.name} lost escaping entirely"


def test_incident_detail_contains_explanation_and_gaps(settings):
    incident = _seed_journal(settings)
    renderer = ReportRenderer(settings, IncidentManager(settings.data_dir / "incidents"))
    path = renderer.render_incident(incident)
    html = path.read_text(encoding="utf-8")
    assert "Detection explanation" in html
    assert "Evidence coverage" in html
    assert "R-DECOY-001" in html


def test_reports_never_touch_the_journal(settings):
    """The renderer must not append to or rewrite evidence."""
    incident = _seed_journal(settings)
    journal_path = settings.data_dir / "events" / "events.jsonl"
    before = journal_path.read_text()
    # Re-render twice; journal bytes must be unchanged.
    renderer = ReportRenderer(settings, IncidentManager(settings.data_dir / "incidents"))
    renderer.render_all()
    renderer.render_all()
    after = journal_path.read_text()
    assert before == after
