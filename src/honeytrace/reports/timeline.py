"""Report A - the attack timeline builder.

Reads normalized events and incident records from the local evidence store
(read-only; the journal is never edited). Produces a chronological structure
for the HTML timeline with:

* event time vs collection time (late arrivals stay visible),
* per-event severity indicator, source, actor/session, process ancestry,
* artifact references (shown only when the file exists),
* a dedicated evidence-gaps section (sensor downtime, dropped events,
  unattributed events, unverified artifacts),
* filters (time range, actor, event type, severity, source).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.evidence.journal import iter_raw_events
from honeytrace.evidence.manifest import ArtifactManifest
from honeytrace.models.events import event_sort_key
from honeytrace.models.incidents import SEVERITY_ORDER, Incident

SEVERITY_BY_EVENT = {
    "decoy.token_callback": "critical",
    "auth.login_failure": "medium",
    "priv.escalation": "high",
    "baseline.change": "high",
    "response.action": "high",
    "health.alert": "medium",
    "health.gap": "low",
}


class TimelineBuilder:
    def __init__(self, settings, incident_manager=None):
        self.settings = settings
        self.events_dir = settings.data_dir / "events"
        self.manifest = ArtifactManifest(settings.data_dir / "manifests")
        self.incident_manager = incident_manager

    # ------------------------------------------------------------------ #

    def build(
        self,
        incident: Optional[Incident] = None,
        event_filter: Optional[Dict[str, Any]] = None,
        limit: int = 5000,
    ) -> Dict[str, Any]:
        wanted_ids = set(incident.event_ids) if incident else None
        session_ids = set(incident.session_ids) if incident else set()
        window_start = window_end = None
        if incident and incident.first_event_utc and incident.last_event_utc:
            from datetime import datetime, timedelta, timezone

            def _parse(ts: str):
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))

            try:
                window_start = _parse(incident.first_event_utc) - timedelta(seconds=60)
                window_end = _parse(incident.last_event_utc) + timedelta(seconds=600)
            except ValueError:
                window_start = window_end = None

        events: List[Dict[str, Any]] = []
        for ev in iter_raw_events(self.events_dir, limit=limit):
            if wanted_ids is not None:
                in_incident = ev.get("event_id") in wanted_ids
                # Session-related backfill: events from the same session inside
                # the incident's event-time window (with margins). Separate
                # sessions are never pulled in.
                in_session = False
                if session_ids and window_start and ev.get("session_id") in session_ids:
                    ts = ev.get("timestamp_utc") or ""
                    try:
                        from datetime import datetime

                        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        in_session = window_start <= t <= window_end
                    except ValueError:
                        in_session = False
                if not (in_incident or in_session):
                    continue
            if event_filter and not self._matches_filter(ev, event_filter):
                continue
            events.append(ev)

        events.sort(key=event_sort_key)
        cards = [self._event_card(ev) for ev in events]

        gaps = self._evidence_gaps(events, incident, cards)
        return {
            "incident": incident.to_dict() if incident else None,
            "title": f"Attack timeline - {incident.incident_id}" if incident else "Attack timeline - all events",
            "events": cards,
            "event_count": len(cards),
            "gaps": gaps,
            "filters": event_filter or {},
        }

    # ------------------------------------------------------------------ #

    @staticmethod
    def _matches_filter(ev: Dict[str, Any], f: Dict[str, Any]) -> bool:
        if f.get("event_type") and ev.get("event_type") != f["event_type"]:
            return False
        if f.get("source") and ev.get("source") != f["source"]:
            return False
        actor = ev.get("actor") or {}
        if f.get("actor") and (actor.get("username") or actor.get("uid")) != f["actor"]:
            return False
        if f.get("session_id") and ev.get("session_id") != f["session_id"]:
            return False
        ts = ev.get("timestamp_utc") or ""
        if f.get("from") and ts < f["from"]:
            return False
        if f.get("to") and ts > f["to"]:
            return False
        sev = SEVERITY_BY_EVENT.get(ev.get("event_type", ""), "info")
        if f.get("severity") and SEVERITY_ORDER.get(sev, 0) < SEVERITY_ORDER.get(f["severity"], 0):
            return False
        return True

    def _event_card(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        event_type = ev.get("event_type", "unknown")
        severity = SEVERITY_BY_EVENT.get(event_type, "info")
        if ev.get("decoy_id"):
            severity = max(severity, "high", key=lambda s: SEVERITY_ORDER[s])
        process = ev.get("process") or {}
        actor = ev.get("actor") or {}
        target = ev.get("target") or {}
        network = ev.get("network") or {}
        artifacts = []
        for art in self.manifest.find_by_event(ev.get("event_id", "")):
            exists = Path(art["path"]).exists()
            artifacts.append(
                {
                    "artifact_id": art["artifact_id"],
                    "path": art["path"],
                    "type": art["type"],
                    "size": art["size"],
                    "sha256": art["sha256"],
                    "available": exists,
                    # Shown in the UI only when the file exists (verified at render).
                    "verified": exists,
                }
            )
        return {
            "event_id": ev.get("event_id"),
            "event_type": event_type,
            "severity": severity,
            "source": ev.get("source"),
            "timestamp_utc": ev.get("timestamp_utc"),
            "observed_at_utc": ev.get("observed_at_utc"),
            "late_arrival": bool(
                ev.get("observed_at_utc") and ev.get("timestamp_utc")
                and ev["observed_at_utc"] > ev["timestamp_utc"]
            ),
            "actor": actor,
            "session_id": ev.get("session_id"),
            "process": process,
            "ancestry": process.get("ancestry") or [],
            "target": target,
            "network": network,
            "decoy_id": ev.get("decoy_id"),
            "details": ev.get("details") or {},
            "rule_matches": ev.get("rule_matches") or [],
            "incident_id": ev.get("incident_id"),
            "observation": ev.get("observation", "observed"),
            "confidence": ev.get("confidence"),
            "artifacts": artifacts,
        }

    def _evidence_gaps(
        self,
        events: List[Dict[str, Any]],
        incident: Optional[Incident],
        cards: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        gap_events = [e for e in events if e.get("event_type") == "health.gap"]
        unattributed = [
            e for e in events
            if e.get("source") == "filesystem" and not (e.get("process") or {}).get("pid")
        ]
        dropped = 0
        for e in events:
            if e.get("event_type") == "daemon.stop":
                dropped = (e.get("details") or {}).get("dropped_pipeline", 0)
        coverage = incident.evidence_coverage if incident else None
        artifacts_unavailable = [
            a["path"] for card in cards for a in card.get("artifacts", []) if not a["available"]
        ]
        return {
            "sensor_gaps": [
                {"timestamp_utc": e.get("timestamp_utc"), "detail": (e.get("details") or {}).get("gap")}
                for e in gap_events
            ],
            "unattributed_file_events": len(unattributed),
            "note_unattributed": (
                "filesystem events without process attribution mean audit telemetry was "
                "unavailable for that moment - the action is observed, the actor is unknown"
            ),
            "dropped_events": dropped,
            "coverage": coverage.to_dict() if coverage else None,
            "artifacts_unavailable": artifacts_unavailable,
        }
