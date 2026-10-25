"""Integration: replay mode over the deterministic evaluation corpus.

The same benign/attack traces run against the shipped ruleset to compare
detection outcomes and false-positive behavior - the base for repeatable
rule evaluation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from honeytrace.engine.normalize import Normalizer
from honeytrace.engine.rules import RuleEngine
from honeytrace.models.events import Event

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"


def _replay(settings, name: str):
    engine = RuleEngine(settings.rules)
    normalizer = Normalizer()
    matches = []
    count = 0
    with (SCENARIOS / name).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            ev = normalizer.normalize(raw)
            if ev is None:
                continue
            count += 1
            matches.extend(engine.on_event(ev))
    return count, matches


def test_corpus_benign_zero_false_positives(settings):
    count, matches = _replay(settings, "benign.jsonl")
    assert count == 6
    assert matches == [], f"benign trace raised {len(matches)} false positive(s)"


def test_corpus_deterministic(settings):
    """Replaying the same trace twice yields identical detections.

    Event IDs are random per run by design; the detection signature is the
    rule fired plus its threshold accounting.
    """
    _, first = _replay(settings, "attack_decoy_read.jsonl")
    _, second = _replay(settings, "attack_decoy_read.jsonl")
    sig1 = [(m.rule_id, tuple(sorted(m.threshold.items()))) for m in first]
    sig2 = [(m.rule_id, tuple(sorted(m.threshold.items()))) for m in second]
    assert sig1 == sig2


def test_corpus_attack_matrix(settings):
    expectations = {
        "attack_decoy_read.jsonl": {"R-DECOY-001", "R-CANARY-010", "R-SESSION-004", "R-RECON-005"},
        "attack_bulk.jsonl": {"R-BULK-002"},
        "attack_exfil.jsonl": {"R-EXFIL-011"},
    }
    # NOTE: expectations use the SHIPPED config/rules.yml (load_settings).
    from honeytrace.config import load_settings

    root = Path(__file__).resolve().parents[2]
    shipped = load_settings(root, strict=False)
    engine = RuleEngine(shipped.rules)
    normalizer = Normalizer()
    for scenario, expected in expectations.items():
        fired = set()
        with (SCENARIOS / scenario).open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                try:
                    ev = Event.model_validate(_coerce(raw, normalizer))
                except Exception:
                    continue
                fired |= {m.rule_id for m in engine.on_event(ev)}
        missing = expected - fired
        assert not missing, f"{scenario}: rules {missing} did not fire"
        fired_all = fired
    # Shipped ruleset sanity: no rule fires on benign.
    fired_benign = set()
    engine2 = RuleEngine(shipped.rules)
    with (SCENARIOS / "benign.jsonl").open("r", encoding="utf-8") as fh:
        for line in fh:
            raw = json.loads(line.strip())
            ev = Event.model_validate(_coerce(raw, normalizer))
            fired_benign |= {m.rule_id for m in engine2.on_event(ev)}
    assert not fired_benign, f"benign trace triggered shipped rules: {fired_benign}"


def _coerce(raw, normalizer):
    """Normalize timestamps to the canonical ISO form for Event validation."""
    from honeytrace.engine.normalize import _norm_ts

    raw = dict(raw)
    raw["timestamp_utc"] = _norm_ts(raw.pop("timestamp", None))
    raw["observed_at_utc"] = raw["timestamp_utc"]
    return raw
