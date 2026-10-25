"""Integration: the full pipeline from collector output to reports and export.

A synthetic attack trace flows: normalizer -> journal -> rules -> incidents
-> response (dry-run) -> HTML reports -> case bundle -> bundle verification.
The evidence chain must verify at every step.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from honeytrace.evidence.export import CaseExporter, verify_bundle
from honeytrace.evidence.journal import JournalWriter, iter_raw_events
from honeytrace.evidence.manifest import ArtifactManifest
from honeytrace.evidence.verification import verify_journal
from honeytrace.engine.incidents import IncidentManager
from honeytrace.engine.normalize import Normalizer
from honeytrace.engine.response import ArmingState, ResponseEngine
from honeytrace.engine.rules import RuleEngine
from honeytrace.reports.dashboard import ReportRenderer

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def load_scenario(name: str):
    events = []
    with (SCENARIOS / name).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def run_pipeline(settings, scenario: str):
    """Feed a scenario through the whole engine; return (incidents, journal)."""
    journal = JournalWriter(
        settings.data_dir / "events",
        key_path=settings.data_dir / "state" / "checkpoint.key",
        checkpoint_every=10,
    )
    journal.start()
    normalizer = Normalizer(settings.honeytrace.detection.dedup_window_seconds)
    rules = RuleEngine(settings.rules)
    incidents = IncidentManager(
        settings.data_dir / "incidents",
        incident_gap_seconds=settings.honeytrace.detection.incident_gap_seconds,
    )
    arming = ArmingState(settings.data_dir / "state")
    response = ResponseEngine(settings, arming, journal=journal)
    touched = []
    for raw in load_scenario(scenario):
        event = normalizer.normalize(raw)
        if event is None:
            continue
        journal.append(event.to_dict())
        matches = rules.on_event(event)
        if matches:
            for inc in incidents.on_matches(matches, event=event, sensor_status={"audit": "unavailable"}):
                touched.append(inc)
                for m in matches:
                    rec = response.evaluate(m, inc, event.to_dict())
                    incidents.add_response_record(inc.incident_id, rec.model_dump(mode="json"))
    journal.close()
    return incidents, journal


def test_attack_scenario_end_to_end(settings):
    incidents, journal = run_pipeline(settings, "attack_decoy_read.jsonl")

    # Evidence survived, is chained and verifies. The journal holds the 8
    # scenario events plus response.action records; both are evidence.
    report = verify_journal(settings.data_dir / "events",
                            key_path=settings.data_dir / "state" / "checkpoint.key")
    assert report["ok"], report
    scenario_types = [ev.get("event_type") for ev in iter_raw_events(settings.data_dir / "events")]
    for expected in ("auth.session_open", "exec.command", "file.open", "decoy.token_callback"):
        assert expected in scenario_types
    assert len([t for t in scenario_types if t != "response.action"]) == 8

    # The decoy access raised exactly one incident for that session.
    all_incidents = incidents.all_incidents()
    assert len(all_incidents) == 1
    inc = all_incidents[0]
    rule_ids = {m.rule_id for m in inc.rule_matches}
    assert "R-DECOY-001" in rule_ids
    assert inc.severity == "high"
    assert inc.event_count >= 4
    # Explanation carries thresholds and the reason it fired.
    assert any(m.threshold["observed"] >= 1 for m in inc.rule_matches)
    # Coverage honestly records the unavailable audit sensor.
    assert "audit" in inc.evidence_coverage.missing_sensors or \
           inc.evidence_coverage.notes


def test_benign_scenario_stays_quiet(settings):
    incidents, _ = run_pipeline(settings, "benign.jsonl")
    assert incidents.all_incidents() == [], "benign trace must not raise incidents"


def test_bulk_scenario_fires_threshold_rule(settings):
    incidents, _ = run_pipeline(settings, "attack_bulk.jsonl")
    incs = incidents.all_incidents()
    assert incs, "bulk enumeration must be detected"
    rule_ids = {m.rule_id for m in incs[0].rule_matches}
    assert "R-BULK-002" in rule_ids
    match = next(m for m in incs[0].rule_matches if m.rule_id == "R-BULK-002")
    # Observed count must meet or exceed the rule's own threshold.
    assert match.threshold["observed"] >= match.threshold["required"] >= 5


def test_exfil_scenario_and_response_proposal(settings):
    incidents, _ = run_pipeline(settings, "attack_exfil.jsonl")
    incs = incidents.all_incidents()
    assert incs, "exfil sequence must be detected"
    rule_ids = {m.rule_id for m in incs[0].rule_matches}
    assert "R-EXFIL-011" in rule_ids
    # Observe-mode default: the isolate policy becomes a recorded proposal
    # (the alert-policy matches are applied as alerts).
    actions = incs[0].response_actions
    assert actions
    assert any(a.action == "isolate" for a in actions)
    isolate = next(a for a in actions if a.action == "isolate")
    assert isolate.status in ("proposed", "dry_run")


def test_reports_and_export_roundtrip(settings):
    incidents, _ = run_pipeline(settings, "attack_decoy_read.jsonl")
    inc = incidents.all_incidents()[0]

    renderer = ReportRenderer(settings, incidents)
    paths = renderer.render_all(incident_ids=[inc.incident_id])
    assert all(p.exists() for p in paths)

    # Export a case bundle and verify it on the "other machine".
    exporter = CaseExporter(
        settings,
        ArtifactManifest(settings.data_dir / "manifests"),
        settings.data_dir / "incidents",
    )
    out = settings.data_dir / "reports" / "case.zip"
    index = exporter.export(out, incident_ids=[inc.incident_id])
    assert index["event_count"] > 0
    assert index["chain_report"]["ok"]
    assert out.exists() and out.stat().st_size > 0

    bundle_report = verify_bundle(out)
    assert bundle_report["ok"], bundle_report
    assert bundle_report["events"] == index["event_count"]


def test_unattributed_filesystem_event_still_recorded(settings):
    """A file event with NO actor is journaled and marked as a coverage gap."""
    raw = {
        "event_type": "file.open", "source": "filesystem",
        "target": {"path": "/lab/docs/bait.pdf", "is_decoy": True, "decoy_id": "DCY-1"},
        "decoy_id": "DCY-1",
    }
    n = Normalizer()
    ev = n.normalize(raw)
    assert ev is not None and ev.actor is None
    journal = JournalWriter(settings.data_dir / "events",
                            key_path=settings.data_dir / "state" / "checkpoint.key")
    journal.start()
    journal.append(ev.to_dict())
    journal.close()
    events = list(iter_raw_events(settings.data_dir / "events"))
    assert len(events) == 1
    assert "actor" not in events[0]  # absent, never fabricated
