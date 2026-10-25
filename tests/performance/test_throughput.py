"""Performance measurements (marked slow; run with `pytest -m slow`).

Measures rule-engine throughput and journal write latency on synthetic
events, then asserts generous floors so regressions are visible without
being flaky on slow CI machines. Numbers are printed for the report.
"""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

import pytest

from honeytrace.engine.normalize import Normalizer
from honeytrace.engine.rules import RuleEngine
from honeytrace.evidence.journal import JournalWriter
from honeytrace.models.events import Event

SCENARIOS = Path(__file__).resolve().parents[1] / "scenarios"

pytestmark = pytest.mark.slow


def _corpus(n: int):
    """Expand the attack scenario into n events by cycling its events."""
    raw = []
    with (SCENARIOS / "attack_decoy_read.jsonl").open("r", encoding="utf-8") as fh:
        base = [json.loads(l) for l in fh if l.strip()]
    for i in range(n):
        ev = dict(base[i % len(base)])
        ev = json.loads(json.dumps(ev))  # deep copy
        ev["session_id"] = f"perf-{i}"   # spread across sessions
        raw.append(ev)
    return raw


def test_rules_engine_throughput(settings):
    n = 5000
    engine = RuleEngine(settings.rules)
    normalizer = Normalizer()
    corpus = [_norm(e) for e in _corpus(n)]
    start = time.perf_counter()
    for ev in corpus:
        engine.on_event(ev)
    elapsed = time.perf_counter() - start
    rate = n / elapsed
    print(f"\nrules engine: {rate:,.0f} events/s ({elapsed:.3f}s for {n})")
    assert rate > 500, f"rules throughput collapsed: {rate:.0f}/s"


def test_journal_write_latency(settings):
    n = 2000
    writer = JournalWriter(
        settings.data_dir / "events",
        key_path=settings.data_dir / "state" / "checkpoint.key",
        checkpoint_every=500,
    )
    writer.start()
    latencies = []
    for i in range(n):
        ev = {"event_id": f"perf-{i}", "event_type": "file.open", "source": "synthetic",
              "details": {"i": i, "pad": "x" * 256}}
        t0 = time.perf_counter()
        ok = writer.append(ev)
        latencies.append(time.perf_counter() - t0)
        assert ok
    writer.close()
    p50 = statistics.median(latencies) * 1000
    p99 = sorted(latencies)[int(len(latencies) * 0.99)] * 1000
    print(f"\njournal append: p50={p50:.3f}ms p99={p99:.3f}ms dropped={writer.dropped_events}")
    assert p99 < 25, f"journal append latency too high: p99={p99:.2f}ms"
    assert writer.dropped_events == 0


def test_event_model_overhead(settings):
    n = 3000
    corpus = [_norm(e) for e in _corpus(n)]
    start = time.perf_counter()
    for ev in corpus:
        ev.to_dict()
    elapsed = time.perf_counter() - start
    rate = n / elapsed
    print(f"\nevent serialization: {rate:,.0f} events/s")
    assert rate > 1000


def _norm(raw):
    n = Normalizer()
    ev = n.normalize(raw)
    assert ev is not None
    return ev
