"""Incident lifecycle and store.

Grouping rule: rule matches are folded into the same incident only when the
group key (session/actor/source) is identical AND the events fall inside the
configured gap window. Distinct sessions therefore remain distinct incidents
even when they happen at the same time.

Incidents are stored as one JSON file each under data/incidents/ and are
updated atomically (tmp + rename). The journal remains the raw record;
incidents are derived views and can be rebuilt by replay.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.engine.correlate import SessionTracker
from honeytrace.models.events import Event
from honeytrace.models.incidents import (
    INCIDENT_STATUSES,
    SEVERITY_ORDER,
    EvidenceCoverage,
    Incident,
    ResponseActionRecord,
    RuleMatch,
)


def _utc() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _make_incident_id(ts: Optional[str] = None) -> str:
    return f"INC-{(ts or _utc())[:10].replace('-', '')}-{uuid.uuid4().hex[:8].upper()}"


NEXT_STEPS_BY_SEVERITY = {
    "critical": [
        "Confirm the actor's session in the incident detail view before acting.",
        "If containment is authorized, review the proposed isolation scope.",
        "Preserve evidence: export the case bundle before rebooting the lab.",
    ],
    "high": [
        "Review the attack timeline and confirm which decoys were touched.",
        "Check the process ancestry for the originating session.",
        "Export the case bundle for offline review if needed.",
    ],
    "medium": [
        "Check whether the source endpoint is in your trusted networks list.",
        "Review the activity profile for behavioral context.",
    ],
    "low": [
        "Informational: review at your convenience.",
    ],
    "info": ["Informational."],
}


class IncidentManager:
    def __init__(
        self,
        incidents_dir: Path,
        expected_sensors: Optional[List[str]] = None,
        incident_gap_seconds: int = 900,
        session_tracker: Optional[SessionTracker] = None,
    ):
        self.dir = Path(incidents_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.gap = incident_gap_seconds
        self.session_tracker = session_tracker or SessionTracker()
        self.expected_sensors = expected_sensors or [
            "filesystem", "audit", "auth", "process", "network",
        ]
        self._incidents: Dict[str, Incident] = {}
        self._lock = threading.Lock()
        self._load_existing()

    # -- ingestion ----------------------------------------------------------- #

    def on_matches(
        self,
        matches: List[RuleMatch],
        event: Optional[Event] = None,
        sensor_status: Optional[Dict[str, str]] = None,
    ) -> List[Incident]:
        """Fold rule matches into incidents; return affected incidents."""
        touched: List[Incident] = []
        with self._lock:
            for match in matches:
                inc = self._find_incident(match, event)
                if inc is None:
                    inc = self._create_incident(match, event)
                self._apply_match(inc, match, event, sensor_status)
                if inc not in touched:
                    touched.append(inc)
            for inc in touched:
                self._persist(inc)
        return touched

    def _find_incident(self, match: RuleMatch, event: Optional[Event]) -> Optional[Incident]:
        key = self._identity_key(match, event)
        incoming_ts = (event.timestamp_utc if event else None) or match.fired_at_utc
        for inc in self._incidents.values():
            if inc.status in ("closed",):
                continue
            if inc.actor and inc.actor.get("identity_key") == key:
                last = inc.last_event_utc or inc.updated_at_utc
                if _time_gap_seconds(last, incoming_ts) <= self.gap:
                    return inc
        return None

    def _identity_key(self, match: RuleMatch, event: Optional[Event]) -> str:
        if event and event.session_id:
            return f"session:{event.session_id}"
        if event and event.actor:
            if event.actor.uid is not None:
                return f"uid:{event.actor.uid}"
            if event.actor.username:
                return f"user:{event.actor.username}"
        if event and event.network and event.network.remote_addr:
            return f"ip:{event.network.remote_addr}"
        return f"rule:{match.rule_id}"

    def _create_incident(self, match: RuleMatch, event: Optional[Event]) -> Incident:
        inc_id = _make_incident_id(match.fired_at_utc)
        actor: Dict[str, Any] = {"identity_key": self._identity_key(match, event)}
        if event and event.actor:
            actor.update(
                {
                    "uid": event.actor.uid,
                    "username": event.actor.username,
                    "source_ip": event.actor.source_ip,
                    "tty": event.actor.tty,
                    "auth_method": event.actor.auth_method,
                    "attribution": event.actor.attribution,
                }
            )
        session = self.session_tracker.lookup(
            event.session_id if event else None,
            event.actor.uid if event and event.actor else None,
        )
        if session:
            actor.setdefault("session_state", session.state)
            actor.setdefault("login_utc", session.opened_utc)
        inc = Incident(
            incident_id=inc_id,
            title=match.rule_name,
            severity=match.severity,
            confidence=match.confidence,
            created_at_utc=_utc(),
            updated_at_utc=_utc(),
            actor=actor,
            session_ids=([event.session_id] if event and event.session_id else []),
            first_event_utc=event.timestamp_utc if event else match.fired_at_utc,
            last_event_utc=event.timestamp_utc if event else match.fired_at_utc,
        )
        self._incidents[inc_id] = inc
        return inc

    def _apply_match(
        self,
        inc: Incident,
        match: RuleMatch,
        event: Optional[Event],
        sensor_status: Optional[Dict[str, str]],
    ) -> None:
        now = _utc()
        inc.updated_at_utc = now
        inc.merge_severity(match.severity)
        inc.title = inc.title if inc.title != "Untitled incident" else match.rule_name
        if match.rule_id not in [m.rule_id for m in inc.rule_matches]:
            inc.rule_matches.append(match)
        inc.confidence = round(
            min(0.95, max(m.confidence for m in inc.rule_matches)), 3
        )
        inc.explanation = " | ".join(m.explanation for m in inc.rule_matches[-3:])

        if event:
            if event.event_id not in inc.event_ids:
                inc.event_ids.append(event.event_id)
            inc.event_count = len(inc.event_ids)
            inc.last_event_utc = max(inc.last_event_utc or "", event.timestamp_utc)
            if event.session_id and event.session_id not in inc.session_ids:
                inc.session_ids.append(event.session_id)
            inc.mitre = sorted({*inc.mitre, *match.mitre})

        # Evidence coverage: contributing sources so far + sensor health.
        sources = set()
        for m in inc.rule_matches:
            for eid in m.contributing_event_ids:
                sources.add(m.rule_id)  # placeholder replaced below
        if event:
            sources.discard(event.source)
        coverage = EvidenceCoverage(
            expected_sensors=list(self.expected_sensors),
            contributing_sensors=sorted(sources & set(self.expected_sensors)) or sorted(sources),
        )
        available = {s for s, state in (sensor_status or {}).items() if state == "ok"}
        coverage.missing_sensors = sorted(set(self.expected_sensors) - available)
        coverage.degraded_sensors = sorted(
            s for s, state in (sensor_status or {}).items() if state not in ("ok", "disabled")
        )
        if event and event.process is None and event.source == "filesystem":
            coverage.unattributed_events += 1
            coverage.notes.append(
                "filesystem event has no process attribution - audit telemetry may be missing"
            )
        inc.evidence_coverage = coverage

        inc.uncertainty = sorted({*inc.uncertainty, *match.missing_evidence})
        if event and event.actor and event.actor.attribution != "observed":
            inc.uncertainty.append("actor attribution is inferred, not directly observed")
        inc.recommended_next_steps = NEXT_STEPS_BY_SEVERITY.get(inc.severity, [])

    # -- persistence ---------------------------------------------------------- #

    def _persist(self, inc: Incident) -> None:
        path = self.dir / f"incident-{inc.incident_id}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(inc.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(path)

    def _load_existing(self) -> None:
        if not self.dir.is_dir():
            return
        for f in sorted(self.dir.glob("incident-*.json")):
            try:
                body = json.loads(f.read_text(encoding="utf-8"))
                inc = Incident.model_validate(body)
                self._incidents[inc.incident_id] = inc
            except Exception:
                continue

    # -- operator API (used by dashboard/notifications) ------------------------ #

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def all_incidents(self) -> List[Incident]:
        return sorted(
            self._incidents.values(),
            key=lambda i: (SEVERITY_ORDER.get(i.severity, 0), i.created_at_utc),
            reverse=True,
        )

    def unread_count(self) -> int:
        return sum(1 for i in self._incidents.values() if i.unread and i.status != "closed")

    def active_count(self) -> int:
        return sum(1 for i in self._incidents.values() if i.status in ("open", "acknowledged"))

    def mark_read(self, incident_id: str) -> bool:
        inc = self._incidents.get(incident_id)
        if not inc:
            return False
        inc.unread = False
        with self._lock:
            self._persist(inc)
        return True

    def acknowledge(self, incident_id: str, by: str = "operator") -> bool:
        inc = self._incidents.get(incident_id)
        if not inc:
            return False
        inc.status = "acknowledged"
        inc.unread = False
        inc.acknowledged_by = by
        inc.acknowledged_at_utc = _utc()
        with self._lock:
            self._persist(inc)
        return True

    def add_response_record(self, incident_id: str, record: Any) -> bool:
        inc = self._incidents.get(incident_id)
        if not inc:
            return False
        if not isinstance(record, ResponseActionRecord):
            record = ResponseActionRecord.model_validate(record)
        inc.response_actions.append(record)
        if record.status == "applied" and record.action == "isolate":
            inc.status = "contained"
        with self._lock:
            self._persist(inc)
        return True

    def close(self, incident_id: str) -> bool:
        inc = self._incidents.get(incident_id)
        if not inc:
            return False
        inc.status = "closed"
        inc.unread = False
        inc.closed_at_utc = _utc()
        with self._lock:
            self._persist(inc)
        return True


def _time_gap_seconds(ts_a: Optional[str], ts_b: Optional[str]) -> float:
    """Gap between two event-time ISO stamps (event-time grouping, replay-safe)."""
    try:
        a = datetime.fromisoformat((ts_a or "").replace("Z", "+00:00"))
        b = datetime.fromisoformat((ts_b or "").replace("Z", "+00:00"))
        return abs((b - a).total_seconds())
    except (ValueError, AttributeError):
        return 1e18


def _age_seconds(ts: Optional[str]) -> float:
    if not ts:
        return 1e18
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return abs(datetime.now(timezone.utc).timestamp() - dt.timestamp())
    except ValueError:
        return 1e18
