"""Unit tests: evidence journal - chain, tamper detection, rotation, checkpoints."""

from __future__ import annotations

import json

from honeytrace.evidence.journal import JournalWriter, iter_raw_events, journal_segments, read_events
from honeytrace.evidence.verification import coverage_summary, verify_event_ids_unique, verify_journal


def _writer(tmp_path, **kw):
    return JournalWriter(
        tmp_path / "events",
        key_path=tmp_path / "state" / "checkpoint.key",
        checkpoint_every=kw.pop("checkpoint_every", 10),
        queue_size=kw.pop("queue_size", 100),
        **kw,
    )


def _event(i: int) -> dict:
    return {
        "event_id": f"ev-{i:05d}",
        "event_type": "file.open",
        "source": "synthetic",
        "timestamp_utc": "2026-10-11T10:00:00.000Z",
        "observed_at_utc": "2026-10-11T10:00:00.000Z",
        "details": {"i": i},
    }


def test_roundtrip_and_chain(tmp_path):
    w = _writer(tmp_path)
    w.start()
    for i in range(50):
        assert w.append(_event(i))
    w.close()

    records = list(read_events(tmp_path / "events"))
    assert len(records) == 50
    assert [r["seq"] for r in records] == list(range(1, 51))
    report = verify_journal(tmp_path / "events", key_path=tmp_path / "state" / "checkpoint.key")
    assert report["ok"], report
    assert report["verified"] == 50
    assert report["first_seq"] == 1 and report["last_seq"] == 50
    assert report["breaks"] == [] and report["gaps"] == []


def test_chain_survives_restart(tmp_path):
    """A new writer on the same directory must CONTINUE the chain."""
    w1 = _writer(tmp_path)
    w1.start()
    for i in range(5):
        w1.append(_event(i))
    w1.close()

    w2 = _writer(tmp_path)
    w2.start()
    for i in range(5, 10):
        w2.append(_event(i))
    w2.close()

    records = list(read_events(tmp_path / "events"))
    assert [r["seq"] for r in records] == list(range(1, 11))
    report = verify_journal(tmp_path / "events", key_path=tmp_path / "state" / "checkpoint.key")
    assert report["ok"], report
    assert report["last_seq"] == 10


def test_torn_last_line_is_skipped_on_resume(tmp_path):
    """A hard kill can tear the final line; the next writer skips it."""
    w1 = _writer(tmp_path)
    w1.start()
    for i in range(3):
        w1.append(_event(i))
    w1.close()
    active = tmp_path / "events" / "events.jsonl"
    active.write_text(active.read_text() + '{"seq":4,"prev_hash":"ab')  # torn

    w2 = _writer(tmp_path)
    w2.start()
    w2.append(_event(9))
    w2.close()

    report = verify_journal(tmp_path / "events", key_path=tmp_path / "state" / "checkpoint.key")
    # The torn line stays on disk as a detected gap, but the resumed chain
    # itself must be intact after it.
    assert report["corrupt_lines"] == 1
    assert not report["breaks"]


def test_event_sequence_stamped_into_record(tmp_path):
    w = _writer(tmp_path)
    w.start()
    w.append(_event(1))
    w.close()
    rec = next(iter(read_events(tmp_path / "events")))
    assert rec["event"]["sequence"] == 1
    assert rec["hash"] and rec["prev_hash"] == "0" * 64


def test_tamper_detection(tmp_path):
    w = _writer(tmp_path)
    w.start()
    for i in range(5):
        w.append(_event(i))
    w.close()

    active = tmp_path / "events" / "events.jsonl"
    lines = active.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["event"]["details"]["i"] = 999  # rewrite history
    lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    active.write_text("\n".join(lines) + "\n")

    report = verify_journal(tmp_path / "events")
    assert not report["ok"]
    assert report["breaks"]


def test_gap_detection_when_line_removed(tmp_path):
    w = _writer(tmp_path)
    w.start()
    for i in range(5):
        w.append(_event(i))
    w.close()

    active = tmp_path / "events" / "events.jsonl"
    lines = active.read_text().splitlines()
    del lines[2]  # rip out one record
    active.write_text("\n".join(lines) + "\n")

    report = verify_journal(tmp_path / "events")
    assert not report["ok"]
    assert report["gaps"]


def test_corrupt_line_counts_as_gap(tmp_path):
    w = _writer(tmp_path)
    w.start()
    for i in range(3):
        w.append(_event(i))
    w.close()
    active = tmp_path / "events" / "events.jsonl"
    active.write_text(active.read_text() + "{corrupt json\n")
    report = verify_journal(tmp_path / "events")
    assert not report["ok"]
    assert report["corrupt_lines"] == 1


def test_checkpoints_written_and_hmac_checked(tmp_path):
    w = _writer(tmp_path, checkpoint_every=5)
    w.start()
    for i in range(12):
        w.append(_event(i))
    w.close()
    cps = sorted((tmp_path / "events" / "checkpoints").glob("checkpoint-*.json"))
    assert len(cps) >= 2
    report = verify_journal(tmp_path / "events", key_path=tmp_path / "state" / "checkpoint.key")
    assert report["ok"]
    assert report["checkpoints_checked"] >= 2


def test_rotation_and_pruning(tmp_path):
    w = JournalWriter(
        tmp_path / "events",
        key_path=tmp_path / "state" / "checkpoint.key",
        max_segment_bytes=400,   # force frequent rotation
        max_segments=3,
        checkpoint_every=0,
        queue_size=100,
    )
    w.start()
    for i in range(40):
        w.append(_event(i))
    w.close()
    segments = journal_segments(tmp_path / "events")
    assert len(segments) <= 4  # max_segments + active
    assert len(list(iter_raw_events(tmp_path / "events"))) <= 40


def test_duplicate_event_ids_detected(tmp_path):
    w = _writer(tmp_path)
    w.start()
    w.append(_event(1))
    w.close()
    # Append a copy by hand (simulating a replayed record).
    active = tmp_path / "events" / "events.jsonl"
    lines = active.read_text().splitlines()
    active.write_text("\n".join([*lines, lines[0]]) + "\n")
    dupes = verify_event_ids_unique(tmp_path / "events")
    assert dupes["count"] == 1


def test_queue_full_drops_and_counts(tmp_path):
    w = _writer(tmp_path)
    # Fill the queue without starting the writer thread.
    for i in range(100):
        w.append(_event(i))
    assert w.append(_event(999)) is False
    assert w.dropped_events == 1
    assert w.queue_depth() == 100


def test_coverage_summary(tmp_path):
    w = _writer(tmp_path)
    w.start()
    w.append({**_event(1), "source": "filesystem"})
    w.append({**_event(2), "source": "audit", "event_type": "health.gap"})
    w.close()
    cov = coverage_summary(tmp_path / "events")
    assert cov["events_per_source"]["filesystem"] == 1
    assert cov["gap_events"] == 1
