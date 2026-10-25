"""Unit tests: audit log parser (runs anywhere - no Linux needed)."""

from __future__ import annotations

from pathlib import Path

from honeytrace.collectors.audit import AuditCollector, decode_field, parse_audit_line

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_parse_syscall_line():
    line = (
        'type=SYSCALL msg=audit(1728650000.123:4567): arch=c000003e syscall=257 success=yes '
        'exit=3 a0=3 items=1 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000 tty=pts0 ses=5 '
        'comm="cat" exe="/usr/bin/cat" key="honeytrace"'
    )
    rtype, epoch, serial, fields = parse_audit_line(line)
    assert rtype == "SYSCALL"
    assert serial == 4567
    assert abs(epoch - 1728650000.123) < 0.001
    assert fields["comm"] == "cat"
    assert fields["exe"] == "/usr/bin/cat"
    assert fields["auid"] == "1000"
    assert fields["key"] == "honeytrace"


def test_hex_path_decoding():
    # "/home/lab/bait.pdf" hex-encoded (auditd encodes some paths).
    hexval = "/home/lab/bait.pdf".encode().hex().upper()
    assert decode_field("name", hexval) == "/home/lab/bait.pdf"


def test_quoted_values():
    assert decode_field("comm", '"bash"') == "bash"
    assert decode_field("uid", "1000") == "1000"


def test_execve_argv_parsing():
    line = (
        'type=EXECVE msg=audit(1728650000.200:4568): argc=3 a0="cat" a1="bait" a2="pdf"'
    )
    rtype, epoch, serial, fields = parse_audit_line(line)
    assert rtype == "EXECVE"
    assert fields["a0"] == "cat" and fields["a2"] == "pdf"


def test_non_audit_line_returns_none():
    assert parse_audit_line("Oct 11 10:00:00 host sshd[1]: hi") is None


def test_collector_replays_fixture(tmp_path, settings):
    """Full fixture log -> emitted raw events via the collector's parser."""
    emitted = []
    settings.honeytrace.audit.log_file = str(FIXTURES / "audit_sample.log")
    collector = AuditCollector(emitted.append, settings)
    # Force OK status for replay (the real file exists in fixtures).
    collector.status = "ok"
    collector.parse_file(FIXTURES / "audit_sample.log")
    types = [e["event_type"] for e in emitted]
    assert "exec.command" in types, types
    opens = [e for e in emitted if e["event_type"] == "file.open"]
    assert opens, "expected a file.open from the SYSCALL record"
    assert opens[0]["process"]["pid"] == 5678
    assert opens[0]["actor"]["session_id"] == "audit-ses-5"


def test_fixture_has_decoy_path_event(tmp_path, settings):
    emitted = []
    settings.honeytrace.audit.log_file = str(FIXTURES / "audit_sample.log")
    collector = AuditCollector(emitted.append, settings)
    collector.status = "ok"
    collector.parse_file(FIXTURES / "audit_sample.log")
    bait = [e for e in emitted if "bait" in str((e.get("target") or {}).get("path", ""))]
    assert bait, "monitored-path filter must pass the decoy path through"
