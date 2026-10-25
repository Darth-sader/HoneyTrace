"""The normalized event schema.

Every collector output passes through honeytrace.engine.normalize before it
becomes an Event. The Event is what the rules engine, correlation, journal
and reports all consume - one common shape, one place to redact.

Canonical JSON contract
-----------------------
`canonical_json(event_dict)` produces a byte-stable representation used by
the hash chain. Optional fields that are None are dropped (absent), so a
missing observation and an explicit null never look identical on disk.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from honeytrace.models.actors import ActorRef, FileTarget, NetEndpoint, ProcessRef


def utc_now_iso() -> str:
    """Current time, UTC, ISO-8601 with millisecond precision and Z suffix."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def iso_from_epoch(epoch: float) -> str:
    """Convert epoch seconds to the canonical UTC ISO form."""
    dt = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def new_event_id() -> str:
    return uuid.uuid4().hex


EVENT_SOURCES = frozenset(
    {
        "filesystem",
        "audit",
        "process",
        "auth",
        "network",
        "pcap",
        "canary",
        "session",
        "baseline",
        "detection",
        "response",
        "health",
        "deception",
        "synthetic",
    }
)


class Event(BaseModel):
    """One normalized observation.

    timestamp_utc   - when the thing happened (event time, OS-provided when
                      available)
    observed_at_utc - when HoneyTrace collected it (collection time). These
                      are separate so late-arriving events stay honest.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=new_event_id)
    event_type: str
    source: str

    timestamp_utc: str = Field(default_factory=utc_now_iso)
    observed_at_utc: str = Field(default_factory=utc_now_iso)

    actor: Optional[ActorRef] = None
    session_id: Optional[str] = None
    process: Optional[ProcessRef] = None
    target: Optional[FileTarget] = None
    network: Optional[NetEndpoint] = None

    decoy_id: Optional[str] = None
    # Free-form collector payload. Values are redacted by the normalizer
    # before durable storage.
    details: Dict[str, Any] = Field(default_factory=dict)
    # Evidence references (artifact ids from the manifest).
    artifacts: List[str] = Field(default_factory=list)

    # "observed" (directly seen) | "inferred" (derived) | "unknown"
    observation: str = "observed"
    # How strongly this single event supports its own attribution.
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    # Set by rules engine when a match references this event.
    rule_matches: List[str] = Field(default_factory=list)
    # Set by the incident engine when grouped.
    incident_id: Optional[str] = None

    # Filled by the journal: ordered sequence number of the record.
    sequence: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Canonical dict: optional-None fields are absent, not null."""
        data = self.model_dump(mode="json")
        return {k: v for k, v in data.items() if v is not None} | {
            k: v
            for k, v in (
                ("details", self.details or None),
                ("artifacts", self.artifacts or None),
                ("rule_matches", self.rule_matches or None),
            )
            if v
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def canonical_json(obj: Any) -> str:
    """Byte-stable JSON: sorted keys, compact, UTF-8, no NaN."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def event_sort_key(event: Dict[str, Any]):
    """Sort by event time, then observed time, then id (stable order)."""
    return (
        event.get("timestamp_utc") or "",
        event.get("observed_at_utc") or "",
        event.get("event_id") or "",
    )
