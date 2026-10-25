"""Unit tests: normalization, redaction and duplicate suppression."""

from __future__ import annotations

from honeytrace.engine.normalize import Normalizer, redact_value


def test_redacts_password_shaped_strings():
    text = "config: password=Sup3rSecret! and api_key=abcd1234efgh"
    out = redact_value(text)
    assert "Sup3rSecret" not in out
    assert "abcd1234efgh" not in out
    assert "REDACTED" in out


def test_redacts_private_key_blocks():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    assert "MIIEpAIBAAKCAQEA" not in redact_value(text)


def test_redaction_recurses_into_details():
    raw = {"cmd": "login --password=hunter2", "nested": {"token": "abcdef123456789"}}
    out = redact_value(raw)
    assert "hunter2" not in out["cmd"]
    assert "abcdef123456789" not in out["nested"]["token"]


def test_long_values_bounded():
    raw = "x" * 5000
    out = redact_value(raw)
    assert len(out) < 2200
    assert "truncated" in out


def test_normalizer_builds_event_and_keeps_absent_fields():
    n = Normalizer()
    ev = n.normalize(
        {
            "event_type": "file.open",
            "source": "filesystem",
            "target": {"path": "/lab/docs/bait.pdf"},
            "details": {"mask": 32},
        }
    )
    assert ev is not None
    assert ev.actor is None          # no actor -> absent, never guessed
    assert ev.details["mask"] == 32


def test_normalizer_rejects_malformed():
    n = Normalizer()
    assert n.normalize({"source": "x"}) is None            # no event_type
    assert n.normalize({"event_type": "file.open"}) is None  # no source


def test_dedup_suppresses_same_action_in_window():
    n = Normalizer(dedup_window_seconds=60)
    raw = {
        "event_type": "file.open",
        "source": "filesystem",
        "target": {"path": "/lab/docs/a.txt"},
        "actor": {"uid": 1000},
    }
    first = n.normalize(raw)
    second = n.normalize(dict(raw))
    assert first is not None
    assert second is None  # duplicate suppressed


def test_dedup_keeps_distinct_actions():
    n = Normalizer(dedup_window_seconds=60)
    base = {"source": "filesystem", "target": {"path": "/lab/docs/a.txt"}, "actor": {"uid": 1000}}
    assert n.normalize({**base, "event_type": "file.open"}) is not None
    assert n.normalize({**base, "event_type": "file.modify"}) is not None  # different action
    assert n.normalize({**base, "event_type": "file.open", "target": {"path": "/lab/docs/b.txt"}}) is not None


def test_dedup_separates_actors():
    n = Normalizer(dedup_window_seconds=60)
    raw = {"event_type": "file.open", "source": "filesystem", "target": {"path": "/x"}, "actor": {"uid": 1}}
    assert n.normalize(raw) is not None
    raw2 = {"event_type": "file.open", "source": "filesystem", "target": {"path": "/x"}, "actor": {"uid": 2}}
    assert n.normalize(raw2) is not None  # different actor never suppressed
