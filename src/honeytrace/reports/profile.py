"""Report B - the activity profile builder.

Answers three questions with evidence, alternatives and uncertainty:
    What did this session do?
    What evidence supports each conclusion?
    What remains unknown?

Identity caveat baked into the output: an IP address does not identify a
person, and a behavior pattern does not prove a common attacker. Direct
observations are separated from correlations and from enrichment.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from honeytrace.evidence.journal import iter_raw_events
from honeytrace.models.incidents import Incident


class ProfileBuilder:
    def __init__(self, settings, session_tracker=None):
        self.settings = settings
        self.events_dir = settings.data_dir / "events"
        self.session_tracker = session_tracker

    def build(self, incident: Incident) -> Dict[str, Any]:
        events = self._incident_events(incident)
        actor = incident.actor or {}

        profile: Dict[str, Any] = {
            "incident_id": incident.incident_id,
            "actor_id": self._pseudonymous_id(incident),
            "generated_from": {"event_count": len(events), "incident_id": incident.incident_id},
            "identity_context": self._identity_context(incident, actor),
            "session_context": self._session_context(incident, events),
            "network_context": self._network_context(events),
            "process_context": self._process_context(events),
            "behavior": self._behavior(events),
            "decoy_interest": self._decoy_interest(events),
            "evidence_map": self._evidence_map(incident, events),
            "limitations": self._limitations(),
        }
        return profile

    # ------------------------------------------------------------------ #

    def _incident_events(self, incident: Incident) -> List[Dict[str, Any]]:
        """Events directly referenced plus session-related events of this
        incident (same session ids; other sessions are never merged)."""
        from datetime import datetime, timedelta

        wanted = set(incident.event_ids)
        sessions = set(incident.session_ids)
        out = []
        for ev in iter_raw_events(self.events_dir):
            if ev.get("event_id") in wanted or ev.get("incident_id") == incident.incident_id:
                out.append(ev)
                continue
            if sessions and ev.get("session_id") in sessions:
                try:
                    t = datetime.fromisoformat((ev.get("timestamp_utc") or "").replace("Z", "+00:00"))
                    start = datetime.fromisoformat((incident.first_event_utc or "").replace("Z", "+00:00")) - timedelta(seconds=60)
                    end = datetime.fromisoformat((incident.last_event_utc or "").replace("Z", "+00:00")) + timedelta(seconds=600)
                    if start <= t <= end:
                        out.append(ev)
                except ValueError:
                    pass
        return out

    @staticmethod
    def _pseudonymous_id(incident: Incident) -> str:
        """Pseudonymous handle: derived from session/endpoint, not a name."""
        actor = incident.actor or {}
        parts = [actor.get("source_ip"), actor.get("uid"), (incident.session_ids or ["-"])[0]]
        base = "-".join(str(p) for p in parts if p not in (None, "-"))
        return f"actor:{base or incident.incident_id}"

    def _identity_context(self, incident: Incident, actor: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "uid": actor.get("uid"),
            "username": actor.get("username"),
            "attribution": actor.get("attribution", "unknown"),
            "caveat": (
                "Usernames and UIDs are OS-level accounts. They do not prove "
                "which human used the account."
            ),
        }

    def _session_context(self, incident: Incident, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        auth_events = [e for e in events if e.get("event_type", "").startswith("auth.")]
        session = None
        if self.session_tracker and incident.session_ids:
            session = self.session_tracker.lookup(incident.session_ids[0])
        return {
            "session_ids": incident.session_ids,
            "login_method": next(
                ((e.get("actor") or {}).get("auth_method") for e in auth_events
                 if (e.get("actor") or {}).get("auth_method")),
                None,
            ),
            "auth_events": len(auth_events),
            "first_seen": incident.first_event_utc,
            "last_seen": incident.last_event_utc,
            "tracked_session_state": session.state if session else "unknown",
            "tty": next(
                ((e.get("actor") or {}).get("tty") for e in events if (e.get("actor") or {}).get("tty")),
                None,
            ),
        }

    def _network_context(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        endpoints: Dict[str, Dict[str, Any]] = {}
        for ev in events:
            net = ev.get("network") or {}
            remote = net.get("remote_addr")
            if not remote:
                continue
            entry = endpoints.setdefault(
                remote, {"remote_addr": remote, "connections": 0, "processes": set(), "enrichment": None}
            )
            entry["connections"] += 1
            if net.get("owner_process"):
                entry["processes"].add(net["owner_process"])
            enr = net.get("enrichment")
            if enr:
                entry["enrichment"] = enr
        for entry in endpoints.values():
            entry["processes"] = sorted(entry["processes"])
        outbound = [e for e in events if (e.get("network") or {}).get("direction") == "outbound"]
        return {
            "endpoints": list(endpoints.values()),
            "outbound_attempts": len(outbound),
            "enrichment_caveat": (
                "Reverse DNS / GeoIP / RDAP data is approximate enrichment of an IP "
                "address. It is not the identity of any person."
            ),
        }

    def _process_context(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        procs: Dict[str, Dict[str, Any]] = {}
        execs = []
        for ev in events:
            proc = ev.get("process") or {}
            pid = proc.get("pid")
            if pid:
                key = f"{pid}:{proc.get('start_time') or ''}"
                entry = procs.setdefault(
                    key, {"pid": pid, "exe": proc.get("exe"), "cmdline": proc.get("cmdline") or [], "events": 0}
                )
                entry["events"] += 1
            if ev.get("event_type") == "exec.command":
                execs.append(
                    {
                        "timestamp_utc": ev.get("timestamp_utc"),
                        "argv": (ev.get("details") or {}).get("argv") or proc.get("cmdline") or [],
                        "session_id": ev.get("session_id"),
                    }
                )
        ancestry_roots = []
        for ev in events:
            for step in (ev.get("process") or {}).get("ancestry") or []:
                ancestry_roots.append(step)
        return {
            "processes": list(procs.values()),
            "exec_commands": execs[:100],
            "exec_command_count": len(execs),
            "observed_ancestry_steps": [list(a) for a in dict.fromkeys(map(tuple, ancestry_roots))][:20],
        }

    def _behavior(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_type = Counter(e.get("event_type", "unknown") for e in events)
        per_path = Counter((e.get("target") or {}).get("path") for e in events if e.get("target"))
        # Rapid enumeration heuristic (reported as observation, not proof).
        opens = [e for e in events if e.get("event_type") in ("file.open", "file.access")]
        rapid = len(opens) >= 20
        modifications = [e for e in events if e.get("event_type") in ("file.modify", "file.create", "file.delete")]
        return {
            "event_counts": dict(by_type),
            "most_accessed_paths": per_path.most_common(10),
            "rapid_enumeration_observed": rapid,
            "rapid_enumeration_note": (
                "heuristic based on open/access event density; interactive tools "
                "(indexers, editors) can also cause this"
            ),
            "file_modifications": len(modifications),
            "alternative_explanations": [
                "legitimate automation or backup tooling on the same paths",
                "antivirus or file indexer scanning decoy directories",
                "the operator's own maintenance session if allowlists are incomplete",
            ],
        }

    def _decoy_interest(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        touched: Dict[str, Dict[str, Any]] = {}
        for ev in events:
            decoy_id = ev.get("decoy_id")
            if not decoy_id:
                continue
            entry = touched.setdefault(
                decoy_id,
                {"decoy_id": decoy_id, "path": (ev.get("target") or {}).get("path"), "interactions": []},
            )
            entry["interactions"].append(
                {"event_type": ev.get("event_type"), "timestamp_utc": ev.get("timestamp_utc")}
            )
        callbacks = [e for e in events if e.get("event_type") == "decoy.token_callback"]
        return {
            "decoys_touched": list(touched.values()),
            "token_callbacks": [
                {
                    "timestamp_utc": e.get("timestamp_utc"),
                    "decoy_id": e.get("decoy_id"),
                    "remote": (e.get("network") or {}).get("remote_addr"),
                }
                for e in callbacks
            ],
            "caveat": (
                "A token callback may be produced by a document previewer rather than "
                "the intruder; correlate with process telemetry before attributing."
            ),
        }

    @staticmethod
    def _evidence_map(incident: Incident, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Observation vs correlation vs enrichment, per conclusion."""
        direct: List[str] = []
        correlated: List[str] = []
        enriched: List[str] = []
        for ev in events:
            obs = ev.get("observation", "observed")
            line = f"{ev.get('event_type')} @ {ev.get('timestamp_utc')}"
            if obs == "observed":
                direct.append(line)
            else:
                correlated.append(line)
            if ev.get("source") == "network" and (ev.get("network") or {}).get("enrichment"):
                enriched.append(line)
        for m in incident.rule_matches:
            correlated.append(f"rule {m.rule_id}: {m.explanation}")
        return {
            "direct_observations": direct[:100],
            "correlations": correlated[:100],
            "enrichment": enriched[:50],
            "confidence": incident.confidence,
            "coverage": incident.evidence_coverage.to_dict() if incident.evidence_coverage else None,
        }

    @staticmethod
    def _limitations() -> List[str]:
        return [
            "This profile is a reconstruction from available sensors; it is not complete truth.",
            "Attribution of a person is out of scope: accounts and IPs are not identities.",
            "Root-level attackers can disable sensors or rewrite local evidence (see README).",
            "Enrichment (GeoIP/ASN/RDAP) describes network ownership, not individuals.",
        ]
