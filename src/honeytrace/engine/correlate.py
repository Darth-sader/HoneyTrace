"""Correlation: sessions, actor linking and causal reconstruction.

* SessionTracker maintains login session state (opened/active/closed/
  unknown) fed by auth events, so incidents and profiles can name the
  session context of an action.
* correlate_key / events_share_evidence implement the conservative linking
  rule: separate actors or sessions stay separate unless shared evidence
  (session id, process ancestry, source endpoint) supports linking.
* build_causal_graph produces an evidence-linked event graph for an
  incident, with explicit uncertainty on every inferred edge.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from honeytrace.models.events import Event


class Session:
    __slots__ = ("session_id", "username", "uid", "source_ip", "tty", "auth_method",
                 "state", "opened_utc", "last_seen_utc", "closed_utc", "source")

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.username: Optional[str] = None
        self.uid: Optional[int] = None
        self.source_ip: Optional[str] = None
        self.tty: Optional[str] = None
        self.auth_method: Optional[str] = None
        self.state = "unknown"  # opened | active | closed | unknown
        self.opened_utc: Optional[str] = None
        self.last_seen_utc: Optional[str] = None
        self.closed_utc: Optional[str] = None
        self.source = "auth"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "username": self.username,
            "uid": self.uid,
            "source_ip": self.source_ip,
            "tty": self.tty,
            "auth_method": self.auth_method,
            "state": self.state,
            "opened_utc": self.opened_utc,
            "last_seen_utc": self.last_seen_utc,
            "closed_utc": self.closed_utc,
        }


class SessionTracker:
    """Session state machine fed by normalized auth.* events."""

    def __init__(self) -> None:
        self.sessions: Dict[str, Session] = {}
        # Indexes for lookups from process/auth context.
        self.by_uid: Dict[int, List[str]] = {}
        self.by_source: Dict[str, List[str]] = {}

    def observe(self, event: Event) -> Optional[Session]:
        if event.source != "auth" or not event.event_type.startswith("auth."):
            return None
        etype = event.event_type
        sid = event.session_id
        if not sid:
            # Derive a stable pseudo-id for sessions without an OS id.
            uid = event.actor.uid if event.actor else None
            ip = event.actor.source_ip if event.actor else None
            tty = event.actor.tty if event.actor else None
            sid = f"derived:{uid}:{ip}:{tty}:{event.timestamp_utc[:19]}"
        session = self.sessions.setdefault(sid, Session(sid))

        actor = event.actor
        if actor:
            session.username = actor.username or session.username
            session.uid = actor.uid if actor.uid is not None else session.uid
            session.source_ip = actor.source_ip or session.source_ip
            session.tty = actor.tty or session.tty
            session.auth_method = actor.auth_method or session.auth_method

        if etype in ("auth.session_open", "auth.login_success"):
            session.state = "opened"
            session.opened_utc = session.opened_utc or event.timestamp_utc
        elif etype in ("auth.sudo", "auth.su", "exec.command"):
            if session.state in ("opened", "unknown"):
                session.state = "active"
        elif etype == "auth.session_close":
            session.state = "closed"
            session.closed_utc = event.timestamp_utc

        session.last_seen_utc = event.timestamp_utc
        if session.uid is not None:
            self.by_uid.setdefault(session.uid, []).append(sid)
        if session.source_ip:
            self.by_source.setdefault(session.source_ip, []).append(sid)
        return session

    def lookup(self, session_id: Optional[str], uid: Optional[int] = None) -> Optional[Session]:
        if session_id and session_id in self.sessions:
            return self.sessions[session_id]
        if uid is not None:
            ids = [s for s in self.by_uid.get(uid, []) if self.sessions[s].state != "closed"]
            if ids:
                return self.sessions[ids[-1]]
        return None

    def active_sessions(self) -> List[Session]:
        return [s for s in self.sessions.values() if s.state in ("opened", "active")]


def correlate_key(event: Event) -> Tuple[str, ...]:
    """Best-effort identity key linking events to the same actor/session."""
    parts: List[str] = []
    if event.session_id:
        parts.append(f"session:{event.session_id}")
    if event.actor:
        if event.actor.uid is not None:
            parts.append(f"uid:{event.actor.uid}")
        if event.actor.source_ip:
            parts.append(f"ip:{event.actor.source_ip}")
    if event.process and event.process.pid is not None:
        parts.append(f"pid:{event.process.pid}")
    return tuple(parts) or ("unlinked",)


def events_share_evidence(a: Event, b: Event) -> bool:
    """True only when hard evidence links two events (never time alone)."""
    if a.session_id and b.session_id and a.session_id == b.session_id:
        return True
    pa, pb = a.process, b.process
    if pa and pb and pa.pid is not None and pa.pid == pb.pid:
        if pa.start_time is None or pb.start_time is None or pa.start_time == pb.start_time:
            return True
    if a.actor and b.actor and a.actor.uid is not None and a.actor.uid == b.actor.uid:
        # Same UID is weak; require also same source endpoint or TTY.
        same_ip = a.actor.source_ip and a.actor.source_ip == b.actor.source_ip
        same_tty = a.actor.tty and a.actor.tty == b.actor.tty
        if same_ip or same_tty:
            return True
    return False


def build_causal_graph(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evidence-linked graph of an incident's events.

    Nodes are events. Edges carry a `basis` (session/ancestry/decoy/
    network-owner/time) and an `inferred` flag. Time-only edges are always
    marked inferred - they are ordering hints, not proof of causation.
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    by_id: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        eid = ev.get("event_id")
        if not eid:
            continue
        by_id[eid] = ev
        nodes.append(
            {
                "event_id": eid,
                "event_type": ev.get("event_type"),
                "timestamp_utc": ev.get("timestamp_utc"),
                "source": ev.get("source"),
                "decoy_id": ev.get("decoy_id"),
                "process_pid": (ev.get("process") or {}).get("pid"),
                "session_id": ev.get("session_id"),
                "target_path": (ev.get("target") or {}).get("path"),
            }
        )

    ids = list(by_id.keys())
    for i, eid_a in enumerate(ids):
        a = by_id[eid_a]
        for eid_b in ids[i + 1:]:
            b = by_id[eid_b]
            basis = _edge_basis(a, b)
            if basis:
                edges.append({"from": eid_a, "to": eid_b, "basis": basis[0], "inferred": basis[1]})
    return {"nodes": nodes, "edges": edges}


def _edge_basis(a: Dict[str, Any], b: Dict[str, Any]) -> Optional[Tuple[str, bool]]:
    if a.get("session_id") and a.get("session_id") == b.get("session_id"):
        return ("same-session", False)
    pa, pb = a.get("process") or {}, b.get("process") or {}
    if pa.get("pid") and pa.get("pid") == pb.get("pid") and pa.get("pid") is not None:
        return ("same-process", False)
    if a.get("decoy_id") and a.get("decoy_id") == b.get("decoy_id"):
        return ("same-decoy", False)
    ta, tb = (a.get("target") or {}).get("path"), (b.get("target") or {}).get("path")
    if ta and ta == tb:
        return ("same-target", False)
    na, nb = a.get("network") or {}, b.get("network") or {}
    if na.get("remote_addr") and na.get("remote_addr") == nb.get("remote_addr"):
        return ("same-endpoint", False)
    # Ordering hint only.
    return ("time-adjacent", True)
