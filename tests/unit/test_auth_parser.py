"""Unit tests: auth.log parsers (distribution-specific, tested without Linux)."""

from __future__ import annotations

from pathlib import Path

from honeytrace.collectors.auth import AuthCollector, parse_auth_log_line, parse_auth_message

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_accepted_password():
    parsed = parse_auth_message(
        "sshd", "Accepted password for labuser from 203.0.113.7 port 51234 ssh2"
    )
    assert parsed["event_type"] == "auth.login_success"
    assert parsed["actor"]["username"] == "labuser"
    assert parsed["actor"]["source_ip"] == "203.0.113.7"


def test_accepted_publickey():
    parsed = parse_auth_message(
        "sshd", "Accepted publickey for labuser from 203.0.113.7 port 51234 ssh2"
    )
    assert parsed["event_type"] == "auth.login_success"
    assert "publickey" in parsed["actor"]["auth_method"]


def test_failed_password_and_invalid_user():
    failed = parse_auth_message("sshd", "Failed password for root from 198.51.100.9 port 40000 ssh2")
    assert failed["event_type"] == "auth.login_failure"
    invalid = parse_auth_message("sshd", "Invalid user oracle from 198.51.100.9 port 40001")
    assert invalid["event_type"] == "auth.login_failure"
    assert invalid["actor"]["username"] == "oracle"


def test_session_open_close():
    opened = parse_auth_message("sshd", "pam_unix(sshd:session): session opened for user labuser(uid=1000) by (uid=0)")
    assert opened["event_type"] == "auth.session_open"
    assert opened["actor"]["uid"] == 1000
    closed = parse_auth_message("sshd", "pam_unix(sshd:session): session closed for user labuser")
    assert closed["event_type"] == "auth.session_close"


def test_sudo_command():
    parsed = parse_auth_message(
        "sudo",
        "labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
    )
    assert parsed["event_type"] == "auth.sudo"
    assert parsed["actor"]["tty"] == "pts/0"
    assert "cat" in parsed["command"]


def test_logind_new_session():
    parsed = parse_auth_message("systemd-logind", "New session 42 of user labuser.")
    assert parsed["event_type"] == "auth.session_open"
    assert parsed["session_hint"] == "42"


def test_irrelevant_message_returns_none():
    assert parse_auth_message("cron", "CRON[123]: (root) CMD (run-parts)") is None


def test_full_auth_log_line():
    parsed = parse_auth_log_line(
        "Oct 11 14:03:22 labvm sshd[1234]: Failed password for admin from 198.51.100.9 port 40002 ssh2"
    )
    assert parsed is not None
    assert parsed["event_type"] == "auth.login_failure"
    assert parsed["pid"] == 1234
    assert parsed["timestamp"] is not None


def test_replay_fixture_lines():
    lines = (FIXTURES / "auth_sample.log").read_text().splitlines()
    collector = AuthCollector(lambda e: None, _settings_stub())
    events = collector.replay_lines(lines)
    types = [e["event_type"] for e in events]
    assert "auth.login_success" in types
    assert "auth.login_failure" in types
    assert "auth.session_open" in types
    assert "auth.sudo" in types


def _settings_stub():
    from types import SimpleNamespace

    return SimpleNamespace(honeytrace=SimpleNamespace(auth=SimpleNamespace(source="file", auth_log="x", enabled=True)))
