"""Engine layer: normalize -> rules -> correlate -> incidents -> response."""

from honeytrace.engine.correlate import Session, SessionTracker, build_causal_graph, correlate_key, events_share_evidence
from honeytrace.engine.incidents import IncidentManager
from honeytrace.engine.normalize import Deduplicator, Normalizer
from honeytrace.engine.response import ArmingState, FirewallManager, ResponseEngine
from honeytrace.engine.rules import RuleEngine, condition_matches, group_key_for

__all__ = [
    "Session",
    "SessionTracker",
    "build_causal_graph",
    "correlate_key",
    "events_share_evidence",
    "IncidentManager",
    "Deduplicator",
    "Normalizer",
    "ArmingState",
    "FirewallManager",
    "ResponseEngine",
    "RuleEngine",
    "condition_matches",
    "group_key_for",
]
