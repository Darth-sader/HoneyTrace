"""Deterministic YAML rules engine.

Semantics (deliberately small and explainable - there is no expression
language and no eval()):

* A rule has one or more condition groups. Groups combine per-event
  matchers.
* Group kinds:
    any      - an event satisfies the pattern if it matches any condition
    all      - a complete pattern is one event matching EACH condition;
               pattern count = min over conditions of matching events
    sequence - conditions must match in order, each step consuming one
               event, with first-step to last-step inside window_seconds
* threshold N: the rule fires when N complete patterns occur inside the
  window, counted per group_by key (session_id / actor / source_ip /
  process / global). Separate sessions are always counted separately.
* suppression_seconds: minimum spacing between firings per group key.
* Firing produces a RuleMatch carrying contributing event IDs, observed vs
  required threshold values, an explanation and explicitly-listed missing
  evidence. MITRE references attach only when a rule actually fires.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from honeytrace.config import Rule, RuleCondition, RuleGroup
from honeytrace.models.events import Event
from honeytrace.models.incidents import RuleMatch


def _ts_to_epoch(ts: Optional[str]) -> float:
    if not ts:
        return time.time()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def group_key_for(event: Event, group_by: str) -> str:
    """Correlation key used to count rules separately per actor/session."""
    if group_by == "session_id":
        return event.session_id or f"uid:{event.actor.uid if event.actor else None}"
    if group_by == "actor":
        a = event.actor
        if a and a.uid is not None:
            return f"uid:{a.uid}"
        return f"user:{a.username}" if a and a.username else "actor:unknown"
    if group_by == "source_ip":
        ip = None
        if event.actor:
            ip = event.actor.source_ip
        if not ip and event.network:
            ip = event.network.remote_addr
        return f"ip:{ip or 'unknown'}"
    if group_by == "process":
        p = event.process
        if p and p.pid is not None:
            return f"pid:{p.pid}"
        return "process:unknown"
    return "global"


def condition_matches(cond: RuleCondition, ev: Event) -> bool:
    """Does one event satisfy one condition matcher?"""
    if cond.event_types and ev.event_type not in cond.event_types:
        return False
    if cond.target_is_decoy is not None and ev.target is not None:
        if bool(ev.target.is_decoy) != cond.target_is_decoy:
            return False
    elif cond.target_is_decoy is not None and ev.target is None:
        return False
    if cond.target_path_prefix and (ev.target is None or not ev.target.path.startswith(cond.target_path_prefix)):
        return False
    if cond.process_name and (ev.process is None or ev.process.exe != cond.process_name):
        return False
    if cond.actor_uid is not None and (ev.actor is None or ev.actor.uid != cond.actor_uid):
        return False
    if cond.actor_username and (ev.actor is None or ev.actor.username != cond.actor_username):
        return False
    if cond.source_ip and (ev.actor is None or ev.actor.source_ip != cond.source_ip):
        return False
    if cond.details_field is not None:
        value = _details_get(ev.details, cond.details_field)
        if value != cond.details_value:
            return False
    return True


def _details_get(details: Dict[str, Any], dotted: str) -> Any:
    cur: Any = details
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class _GroupState:
    """Sliding window of matching events for one (rule, group key)."""

    __slots__ = ("events", "per_condition", "partials", "completed", "last_fire")

    def __init__(self) -> None:
        self.events: deque = deque()          # (epoch, Event) matching any condition
        self.per_condition: Dict[int, deque] = defaultdict(deque)
        self.partials: List[Dict[str, Any]] = []  # sequence state machines
        self.completed: deque = deque()       # (epoch, [event ids], steps)
        self.last_fire: float = 0.0


class RuleEngine:
    def __init__(
        self,
        rules: List[Rule],
        sensor_status: Optional[Dict[str, str]] = None,
        clock: Optional[Any] = None,
    ):
        """`clock` is injectable (time.time) for deterministic tests."""
        self.rules = list(rules)
        self._state: Dict[Tuple[str, str], _GroupState] = {}
        self._clock = clock or time.time
        self.sensor_status = sensor_status or {}
        self._touched_keys: set = set()
        self._eval_count = 0
        # Stats for explainability/coverage.
        self.evaluations = 0
        self.suppressed_fires = 0

    # ------------------------------------------------------------------ #

    def on_event(self, event: Event) -> List[RuleMatch]:
        """Feed one event; return matches that fired because of it.

        Time semantics are EVENT time (the event's own timestamp), not wall
        clock - so live collection and offline replay behave identically.
        """
        self.evaluations += 1
        now = _ts_to_epoch(event.timestamp_utc)
        matches: List[RuleMatch] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            match = self._evaluate(rule, event, now)
            if match is not None:
                matches.append(match)
        # Prune only the states this event touched (cheap), and sweep
        # everything occasionally - keeps cost O(events), not O(states).
        self._prune_touched(now)
        self._eval_count = getattr(self, "_eval_count", 0) + 1
        if self._eval_count % 1000 == 0:
            self._prune(now)
        return matches

    def replay(self, events: Iterable[Event]) -> List[RuleMatch]:
        """Offline evaluation of stored events (no sensors involved)."""
        out: List[RuleMatch] = []
        for ev in events:
            out.extend(self.on_event(ev))
        return out

    # ------------------------------------------------------------------ #

    def _state_for(self, rule: Rule, key: str) -> _GroupState:
        return self._state.setdefault((rule.id, key), _GroupState())

    def _evaluate(self, rule: Rule, event: Event, now: float) -> Optional[RuleMatch]:
        key = group_key_for(event, rule.group_by)
        st = self._state_for(rule, key)
        self._touched_keys.add((rule.id, key))
        window = float(rule.window_seconds)
        contribution: List[Tuple[float, List[str]]] = []

        for gi, group in enumerate(rule.conditions):
            if group.kind in ("any", "all"):
                matched = any(condition_matches(c, event) for c in group.conditions)
                if matched:
                    st.events.append((now, event))
                    for ci, cond in enumerate(group.conditions):
                        if condition_matches(cond, event):
                            st.per_condition[ci].append((now, event))
                if group.kind == "all":
                    # complete patterns = min count across conditions
                    counts = [
                        sum(1 for ts, _ in st.per_condition[ci] if now - ts <= window)
                        for ci in range(len(group.conditions))
                    ]
                    observed = min(counts) if counts else 0
                else:
                    observed = sum(1 for ts, _ in st.events if now - ts <= window)
                if observed >= rule.threshold:
                    contribution.append((observed, self._recent_ids(st.events, now, window)))
            else:  # sequence
                completed = self._advance_sequence(rule, group, st, event, now)
                if completed:
                    contribution.append((len(st.completed), completed))

        if not contribution:
            return None

        # Suppression window per (rule, group).
        if rule.suppression_seconds and st.last_fire and (now - st.last_fire) < rule.suppression_seconds:
            self.suppressed_fires += 1
            return None
        st.last_fire = now

        observed = max(int(c[0]) for c in contribution)
        contributing_ids: List[str] = []
        for _, ids in contribution:
            for eid in ids:
                if eid not in contributing_ids:
                    contributing_ids.append(eid)

        return self._build_match(rule, key, observed, contributing_ids, now)

    def _advance_sequence(
        self, rule: Rule, group: RuleGroup, st: _GroupState, event: Event, now: float
    ) -> List[str]:
        """Ordered state machine for a sequence group. Returns completed event
        IDs when this event completes a sequence."""
        completed: List[str] = []
        window = float(rule.window_seconds)
        steps = group.conditions

        # Try to advance existing partials first.
        for partial in st.partials:
            step = partial["step"]
            if step < len(steps) and condition_matches(steps[step], event):
                if now - partial["start"] > window:
                    continue  # expired; leave for pruning
                partial["events"].append(event)
                partial["step"] += 1
                if partial["step"] == len(steps):
                    completed = [e.event_id for e in partial["events"]]
                    st.completed.append((now, completed, len(steps)))
                    partial["done"] = True

        # A matching event also starts a new partial (unless it completed one).
        if steps and condition_matches(steps[0], event) and not completed:
            st.partials.append({"step": 1, "events": [event], "start": now, "done": False})

        st.partials = [p for p in st.partials if not p.get("done") and now - p["start"] <= window]
        while len(st.completed) and now - st.completed[0][0] > window:
            st.completed.popleft()
        return completed

    def _recent_ids(self, dq: deque, now: float, window: float) -> List[str]:
        return [e.event_id for ts, e in dq if now - ts <= window]

    def _prune_touched(self, now: float) -> None:
        max_window = max((float(r.window_seconds) for r in self.rules), default=0.0) + 1.0
        for key in self._touched_keys:
            st = self._state.get(key)
            if st is None:
                continue
            while st.events and now - st.events[0][0] > max_window:
                st.events.popleft()
            for dq in st.per_condition.values():
                while dq and now - dq[0][0] > max_window:
                    dq.popleft()
            st.partials = [p for p in st.partials if now - p["start"] <= max_window]
            while st.completed and now - st.completed[0][0] > max_window:
                st.completed.popleft()
        self._touched_keys.clear()

    def _prune(self, now: float) -> None:
        max_window = max((float(r.window_seconds) for r in self.rules), default=0.0) + 1.0
        dead_keys = []
        for key, st in self._state.items():
            while st.events and now - st.events[0][0] > max_window:
                st.events.popleft()
            for dq in st.per_condition.values():
                while dq and now - dq[0][0] > max_window:
                    dq.popleft()
            st.partials = [p for p in st.partials if now - p["start"] <= max_window]
            while st.completed and now - st.completed[0][0] > max_window:
                st.completed.popleft()
            # Empty long-idle states can be dropped entirely.
            if not st.events and not st.partials and not st.completed and all(
                not dq for dq in st.per_condition.values()
            ):
                dead_keys.append(key)
        for key in dead_keys:
            del self._state[key]

    # ------------------------------------------------------------------ #

    def _build_match(
        self, rule: Rule, key: str, observed: int, event_ids: List[str], now: float
    ) -> RuleMatch:
        # Confidence: rule base weight, adjusted by evidence quality.
        confidence = rule.confidence_weight
        missing: List[str] = []
        if not event_ids:
            missing.append("no contributing event ids recorded")

        # The engine inspects the events it just saw via state; for missing-
        # evidence heuristics we rely on the caller-supplied sensor status
        # plus generic checks.
        if self.sensor_status.get("audit") not in ("ok", None) and rule.id.startswith("R-RECON"):
            missing.append("audit exec telemetry unavailable - command chain is inferred from process scans")
        if self.sensor_status.get("filesystem") == "error":
            missing.append("filesystem sensor unhealthy")

        explanation = (
            f"{rule.name}: {observed} occurrence(s) reached threshold {rule.threshold} "
            f"within {rule.window_seconds}s (group {rule.group_by}={key}). "
            f"Conditions: {'; '.join(g.kind + '[' + '; '.join(c.describe() for c in g.conditions) + ']' for g in rule.conditions)}."
        )
        return RuleMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            confidence=round(min(0.95, max(0.05, confidence)), 3),
            fired_at_utc=datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            contributing_event_ids=event_ids,
            threshold={"required": rule.threshold, "observed": observed, "window_seconds": rule.window_seconds},
            explanation=explanation,
            missing_evidence=missing,
            mitre=list(rule.mitre),
            response_policy=rule.response,
        )
