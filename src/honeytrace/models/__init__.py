"""Typed data models shared across HoneyTrace.

models.events     - the normalized event schema (common event model)
models.actors     - actor, process and target references
models.incidents  - incident, rule match and evidence-coverage records

The models are Pydantic v2 models. Serialization uses a canonical JSON form
(sorted keys, compact separators, UTF-8) so hash-chain records are stable.
"""

from honeytrace.models.actors import (
    ActorRef,
    FileTarget,
    NetEndpoint,
    ProcessRef,
    NetworkEnrichment,
)
from honeytrace.models.events import Event, canonical_json, new_event_id, utc_now_iso
from honeytrace.models.incidents import (
    EvidenceCoverage,
    Incident,
    ResponseActionRecord,
    RuleMatch,
)

__all__ = [
    "ActorRef",
    "FileTarget",
    "NetEndpoint",
    "NetworkEnrichment",
    "ProcessRef",
    "Event",
    "canonical_json",
    "new_event_id",
    "utc_now_iso",
    "EvidenceCoverage",
    "Incident",
    "ResponseActionRecord",
    "RuleMatch",
]
