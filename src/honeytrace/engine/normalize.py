"""Normalizer: collector-specific output -> the common Event schema.

Responsibilities:
1. Convert raw collector dicts (heterogeneous) into validated Event models.
2. Redact credential-shaped strings and bound oversized values BEFORE any
   durable storage.
3. Suppress exact duplicates within a configurable window without dropping
   distinct actions (key = event_type + target + actor, not just time).
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from typing import Any, Dict, Optional

from honeytrace.evidence.hashing import REDACTED, REDACT_PATTERNS
from honeytrace.models.actors import ActorRef, FileTarget, NetEndpoint, ProcessRef
from honeytrace.models.events import Event, iso_from_epoch, utc_now_iso

MAX_STRING_LEN = 2000
DEDUP_CACHE_SIZE = 8192


SENSITIVE_KEY_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential)")


def redact_value(value: Any) -> Any:
    """Recursively redact and bound strings inside a details payload.

    Two layers: credential-shaped substrings inside strings, and ANY value
    stored under a credential-shaped key (e.g. details={"token": "..."}).
    """
    if isinstance(value, str):
        out = value
        for pattern in REDACT_PATTERNS:
            out = pattern.sub(lambda m: f"{m.group(1)}={REDACTED}" if m.lastindex else REDACTED, out)
        if len(out) > MAX_STRING_LEN:
            out = out[:MAX_STRING_LEN] + f"...[truncated {len(value) - MAX_STRING_LEN} chars]"
        return out
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and SENSITIVE_KEY_RE.search(k):
                out[str(k)] = REDACTED
            else:
                out[str(k)] = redact_value(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_value(v) for v in value]
    return value


def _norm_ts(raw: Any) -> str:
    """Accept epoch seconds, epoch ms, or ISO strings."""
    if raw is None:
        return utc_now_iso()
    if isinstance(raw, (int, float)):
        val = float(raw)
        if val > 1e12:  # milliseconds
            val = val / 1000.0
        return iso_from_epoch(val)
    if isinstance(raw, str) and raw:
        return raw
    return utc_now_iso()


def _actor(raw: Optional[Dict[str, Any]]) -> Optional[ActorRef]:
    if not raw:
        return None
    return ActorRef.model_validate({k: v for k, v in raw.items() if v is not None})


def _process(raw: Optional[Dict[str, Any]]) -> Optional[ProcessRef]:
    if not raw:
        return None
    return ProcessRef.model_validate({k: v for k, v in raw.items() if v is not None})


def _target(raw: Optional[Dict[str, Any]]) -> Optional[FileTarget]:
    if not raw:
        return None
    data = dict(raw)
    data.setdefault("path", "")
    return FileTarget.model_validate(data)


def _network(raw: Optional[Dict[str, Any]]) -> Optional[NetEndpoint]:
    if not raw:
        return None
    return NetEndpoint.model_validate({k: v for k, v in raw.items() if v is not None})


class Deduplicator:
    """Bounded, time-windowed duplicate suppression.

    Keyed by (event_type, target path, actor identity). Two DIFFERENT actions
    on the same file (open then modify) are never suppressed against each
    other; the same open repeated within the window is.
    """

    def __init__(self, window_seconds: float = 2.0, max_entries: int = DEDUP_CACHE_SIZE):
        self.window = float(window_seconds)
        self.max_entries = max_entries
        self._seen: "OrderedDict[tuple, float]" = OrderedDict()

    def check(self, key: tuple) -> bool:
        """True = this is a duplicate within the window."""
        now = time.monotonic()
        last = self._seen.get(key)
        if last is not None and (now - last) < self.window:
            self._seen[key] = now
            self._seen.move_to_end(key)
            return True
        self._seen[key] = now
        self._seen.move_to_end(key)
        while len(self._seen) > self.max_entries:
            self._seen.popitem(last=False)
        return False

    def event_key(self, event: Event) -> tuple:
        actor = event.actor
        if actor is not None:
            actor_id = (
                actor.session_id
                or (f"uid:{actor.uid}" if actor.uid is not None else None)
                or actor.username
                or "unknown"
            )
        else:
            actor_id = "unknown"
        # Distinct actions must never collapse: process and network identity
        # disambiguate events that share type/path/actor (e.g. three
        # different commands with no file target).
        proc = event.process
        proc_sig = ""
        if proc is not None:
            proc_sig = proc.exe or (" ".join(proc.cmdline[:3]) if proc.cmdline else "")
        net = event.network
        net_sig = f"{net.remote_addr}:{net.remote_port}" if net else ""
        return (
            event.event_type,
            event.target.path if event.target else "",
            actor_id,
            proc_sig,
            net_sig,
        )


class Normalizer:
    def __init__(self, dedup_window_seconds: float = 2.0):
        self.dedup = Deduplicator(dedup_window_seconds)
        self.duplicates_suppressed = 0

    def normalize(self, raw: Dict[str, Any]) -> Optional[Event]:
        """Raw collector dict -> Event, or None when duplicate/malformed.

        Expected raw keys (all optional except source/event_type):
            timestamp, actor{...}, process{...}, target{path,...},
            network{...}, decoy_id, details{}, observation, confidence
        """
        source = raw.get("source")
        event_type = raw.get("event_type")
        if not source or not event_type:
            return None

        details = redact_value(raw.get("details") or {})
        event = Event(
            event_type=str(event_type),
            source=str(source),
            timestamp_utc=_norm_ts(raw.get("timestamp")),
            observed_at_utc=utc_now_iso(),
            actor=_actor(raw.get("actor")),
            session_id=raw.get("session_id"),
            process=_process(raw.get("process")),
            target=_target(raw.get("target")),
            network=_network(raw.get("network")),
            decoy_id=raw.get("decoy_id"),
            details=details,
            observation=raw.get("observation", "observed"),
            confidence=max(0.0, min(1.0, float(raw.get("confidence", 0.5)))),
        )

        if self.dedup.check(self.dedup.event_key(event)):
            self.duplicates_suppressed += 1
            return None
        return event
