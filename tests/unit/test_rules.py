"""Unit tests: the rules engine (thresholds, sequences, grouping, suppression)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from honeytrace.engine.rules import RuleEngine
from honeytrace.models.actors import ActorRef, FileTarget, ProcessRef
from honeytrace.models.events import Event


def _ts(minutes_ago: float = 0.0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event(etype="file.open", session="s1", uid=1000, decoy=False, path=None, **kw):
    return Event(
        event_type=etype,
        source=kw.pop("source", "filesystem"),
        timestamp_utc=_ts(kw.pop("minutes_ago", 0.0)),
        actor=ActorRef(uid=uid, username=f"u{uid}", session_id=None) if uid else None,
        session_id=session,
        target=FileTarget(path=path or "/lab/f.bin", is_decoy=decoy, decoy_id="DCY-1" if decoy else None),
        **kw,
    )


def _exec_event(exe: str, pid: int = 10, session: str = "s1") -> Event:
    ev = _event("exec.command", source="audit", session=session)
    ev.process = ProcessRef(pid=pid, ppid=1, start_time=1.0, exe=exe, cmdline=[exe])
    return ev


def _engine(settings):
    return RuleEngine(settings.rules, clock=lambda: datetime.now(timezone.utc).timestamp())


# -- single-event + threshold rules ----------------------------------------- #

def test_decoy_rule_fires(settings):
    eng = _engine(settings)
    matches = eng.on_event(_event(decoy=True))
    assert [m.rule_id for m in matches] == ["R-DECOY-001"]
    m = matches[0]
    assert m.threshold["observed"] >= 1 and m.threshold["required"] == 1
    assert m.contributing_event_ids, "contributing event ids must be recorded"
    assert "T1083" in m.mitre  # MITRE attaches only when fired


def test_no_mitre_without_firing(settings):
    eng = _engine(settings)
    assert eng.on_event(_event(decoy=False, path="/lab/normal.bin")) == []


def test_bulk_threshold_needs_count_in_window(settings):
    eng = _engine(settings)
    for i in range(4):
        assert eng.on_event(_event(path=f"/lab/f{i}.bin")) == []
    matches = eng.on_event(_event(path="/lab/f5.bin"))  # 5th within 10s window
    assert [m.rule_id for m in matches] == ["R-BULK-002"]
    assert matches[0].threshold["observed"] == 5


def test_window_expiry_stops_threshold(settings):
    eng = _engine(settings)
    for i in range(4):
        eng.on_event(_event(minutes_ago=9, path=f"/lab/old{i}.bin"))
    # The 4 old events are outside the 10s window; this single event is not enough.
    assert eng.on_event(_event(path="/lab/fresh.bin")) == []


# -- sequence rules ----------------------------------------------------------- #

def test_sequence_requires_order(settings):
    eng = _engine(settings)
    # 'id' before 'whoami' must NOT complete the sequence.
    assert eng.on_event(_exec_event("id")) == []
    assert eng.on_event(_exec_event("whoami")) == []  # sequence is whoami THEN id
    matches = eng.on_event(_exec_event("id"))
    assert [m.rule_id for m in matches] == ["R-SEQ-003"]
    assert len(matches[0].contributing_event_ids) == 2


def test_sequence_step_matcher_is_by_process_name(settings):
    eng = _engine(settings)
    assert eng.on_event(_exec_event("uname")) == []  # wrong step: not whoami


# -- grouping ---------------------------------------------------------------- #

def test_sessions_are_counted_separately(settings):
    eng = _engine(settings)
    for i in range(4):
        assert eng.on_event(_event(session="s1", path=f"/lab/a{i}.bin")) == []
    # A DIFFERENT session's single event must not complete s1's threshold...
    assert eng.on_event(_event(session="s2", path="/lab/b.bin")) == []
    # ...and s1 still needs its own 5th event.
    assert eng.on_event(_event(session="s1", path="/lab/a5.bin")) != []


def test_suppression_blocks_repeated_fires(settings):
    import yaml

    from honeytrace.config import parse_rules

    body = yaml.safe_load(
        """
rules:
  - id: R-SUP-010
    name: suppressed
    severity: low
    conditions:
      - all: [{ event_type: decoy.token_callback }]
    threshold: 1
    window_seconds: 600
    suppression_seconds: 600
    response: log
"""
    )
    rules = parse_rules(body)
    eng = RuleEngine(rules)
    first = eng.on_event(_event("decoy.token_callback", source="canary"))
    assert len(first) == 1
    second = eng.on_event(_event("decoy.token_callback", source="canary"))
    assert second == []  # suppressed within the window
    assert eng.suppressed_fires == 1


def test_match_explains_decision(settings):
    eng = _engine(settings)
    m = eng.on_event(_event(decoy=True))[0]
    assert "R-DECOY-001" in m.explanation or "Decoy" in m.explanation
    assert m.explanation and m.threshold
