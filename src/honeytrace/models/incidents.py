"""Incident, rule-match and evidence-coverage models.

Severity answers "how bad could this be" (from rule definitions).
Confidence answers "how strongly does the evidence support this" (from
attribution quality). The two are computed separately and never mixed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
INCIDENT_STATUSES = ("open", "acknowledged", "contained", "closed")


class RuleMatch(BaseModel):
    """One rule firing, with the full explanation of why it fired."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_name: str
    severity: str = "low"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    fired_at_utc: str
    # Events that satisfied the rule's conditions.
    contributing_event_ids: List[str] = Field(default_factory=list)
    # Threshold accounting, e.g. {"required": 20, "observed": 34, "window_seconds": 10}
    threshold: Dict[str, Any] = Field(default_factory=dict)
    # Human-readable explanation of the decision.
    explanation: str = ""
    # What would have made this match stronger (e.g. "no audit exec record").
    missing_evidence: List[str] = Field(default_factory=list)
    mitre: List[str] = Field(default_factory=list)
    response_policy: str = "log"
    # True when the rule matched but a suppression/allowlist stopped the incident.
    suppressed: bool = False
    suppressed_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class EvidenceCoverage(BaseModel):
    """Which sensors contributed to an incident, and which were missing.

    This is a measure of sensor coverage - it is explicitly NOT a claim that
    the reconstruction is complete or that the evidence proves the truth.
    """

    model_config = ConfigDict(extra="forbid")

    expected_sensors: List[str] = Field(default_factory=list)
    contributing_sensors: List[str] = Field(default_factory=list)
    missing_sensors: List[str] = Field(default_factory=list)
    degraded_sensors: List[str] = Field(default_factory=list)
    dropped_events: int = 0
    unattributed_events: int = 0
    notes: List[str] = Field(default_factory=list)

    @property
    def score(self) -> float:
        """Fraction of expected sensors that contributed. 0..1."""
        if not self.expected_sensors:
            return 0.0
        return len(self.contributing_sensors) / len(self.expected_sensors)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class ResponseActionRecord(BaseModel):
    """Record of a response action (applied or proposed)."""

    model_config = ConfigDict(extra="forbid")

    action_id: str
    incident_id: Optional[str] = None
    rule_id: Optional[str] = None
    action: str                     # log | alert | isolate | throttle
    status: str                     # proposed | applied | failed | rolled_back | dry_run
    target: str                     # uid / session / ip the action scoped to
    reason: str = ""
    previous_state: Optional[str] = None
    rollback_cmd: Optional[str] = None
    rollback_result: Optional[str] = None
    applied_at_utc: Optional[str] = None
    rolled_back_at_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)


class Incident(BaseModel):
    """A grouped, explained set of related events.

    Events from separate actors/sessions stay in separate incidents unless
    shared evidence (process ancestry, session id, source endpoint) supports
    linking them.
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    title: str = "Untitled incident"
    status: str = "open"            # open | acknowledged | contained | closed
    severity: str = "low"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    created_at_utc: str
    updated_at_utc: str
    first_event_utc: Optional[str] = None
    last_event_utc: Optional[str] = None

    actor: Optional[Dict[str, Any]] = None
    session_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    event_count: int = 0

    rule_matches: List[RuleMatch] = Field(default_factory=list)
    mitre: List[str] = Field(default_factory=list)

    evidence_coverage: EvidenceCoverage = Field(default_factory=EvidenceCoverage)
    explanation: str = ""
    uncertainty: List[str] = Field(default_factory=list)
    recommended_next_steps: List[str] = Field(default_factory=list)

    response_actions: List[ResponseActionRecord] = Field(default_factory=list)

    # Operator bookkeeping (kept OUT of the evidence journal).
    unread: bool = True
    acknowledged_by: Optional[str] = None
    acknowledged_at_utc: Optional[str] = None
    closed_at_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)

    def merge_severity(self, other: str) -> None:
        from honeytrace.models.incidents import SEVERITY_ORDER

        if SEVERITY_ORDER.get(other, 0) > SEVERITY_ORDER.get(self.severity, 0):
            self.severity = other
