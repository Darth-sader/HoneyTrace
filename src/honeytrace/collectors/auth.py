"""Authentication/session collector.

Sources, in preference order:
1. systemd journal  - `journalctl -f -o json` (Debian, Ubuntu, Arch, Fedora)
2. /var/log/auth.log tail (fallback when journalctl is unavailable)

Both feed the SAME tested regex parsers (unit-testable without Linux).
Events: auth.login_success, auth.login_failure, auth.session_open,
auth.session_close, auth.sudo, auth.su.

Burst counting of failures is the rules engine's job (R-AUTH-003); this
collector emits every failure and lets thresholds decide what matters.
Log rotation is handled via inode tracking; journal access denial and
duplicate lines are tolerated.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.collectors import (
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    CollectorBase,
)

# ---- parsers (shared between journal MESSAGE and auth.log formats) -------- #

RE_ACCEPTED = re.compile(
    r"Accepted\s+(?P<method>password|publickey|keyboard-interactive\S*)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\w.:%]+)\s+port\s+(?P<port>\d+)"
)
RE_FAILED = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\w.:%]+)"
)
RE_INVALID = re.compile(r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>[\w.:%]+)")
RE_SESSION_OPEN = re.compile(
    r"pam_unix\((?P<service>[\w:-]+):session\): session opened for user "
    r"(?P<user>[^( ]+)(?:\(uid=(?P<useruid>\d+)\))?"
    r"(?: by [^0-9]*\(uid=(?P<byuid>\d+)\))?"
)
RE_SESSION_CLOSE = re.compile(r"pam_unix\((?P<service>[\w:-]+):session\): session closed for user (?P<user>\S+)")
RE_SUDO_CMD = re.compile(
    r"(?P<user>[\w.-]+)\s+:\s+TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"
)
RE_LOGIND_NEW = re.compile(r"New session (?P<session>\d+) of user (?P<user>\S+)\.")
RE_LOGIND_REMOVE = re.compile(r"Removed session (?P<session>\d+)\.")
RE_SU = re.compile(r"Successful su for (?P<user>\S+) by (?P<by>\S+)")


def parse_auth_message(prog: str, message: str) -> Optional[Dict[str, Any]]:
    """One log message -> normalized auth event parts, or None.

    `prog` is the emitting program (sshd, sudo, su, systemd-logind, login...).
    Returns {"event_type", "actor", "service", "command"?}.
    """
    m = RE_ACCEPTED.search(message)
    if m:
        return {
            "event_type": "auth.login_success",
            "actor": {
                "username": m.group("user"),
                "source_ip": m.group("ip"),
                "auth_method": f"ssh-{m.group('method')}" if prog == "sshd" else m.group("method"),
                "attribution": "observed",
            },
            "service": prog,
        }
    m = RE_FAILED.search(message) or RE_INVALID.search(message)
    if m:
        return {
            "event_type": "auth.login_failure",
            "actor": {
                "username": m.group("user"),
                "source_ip": m.group("ip"),
                "attribution": "observed",
            },
            "service": prog,
        }
    m = RE_SESSION_OPEN.search(message)
    if m:
        uid = m.group("useruid") or m.group("byuid")
        return {
            "event_type": "auth.session_open",
            "actor": {
                "username": m.group("user"),
                "uid": int(uid) if uid else None,
                "auth_method": m.group("service"),
                "attribution": "observed",
            },
            "service": m.group("service"),
        }
    m = RE_SESSION_CLOSE.search(message)
    if m:
        return {
            "event_type": "auth.session_close",
            "actor": {"username": m.group("user"), "attribution": "observed"},
            "service": m.group("service"),
        }
    m = RE_SUDO_CMD.search(message)
    if m and prog in ("sudo", "sudo:", "su", "su:"):
        return {
            "event_type": "auth.sudo" if "sudo" in prog else "auth.su",
            "actor": {
                "username": m.group("user"),
                "tty": m.group("tty") if m.group("tty") != "unknown" else None,
                "attribution": "observed",
            },
            "service": prog,
            "command": m.group("command"),
        }
    m = RE_LOGIND_NEW.search(message)
    if m:
        return {
            "event_type": "auth.session_open",
            "actor": {"username": m.group("user"), "attribution": "observed"},
            "service": prog,
            "session_hint": m.group("session"),
        }
    m = RE_SU.search(message)
    if m:
        return {
            "event_type": "auth.su",
            "actor": {"username": m.group("user"), "attribution": "observed"},
            "service": prog,
        }
    return None


def parse_auth_log_line(line: str, year: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """`Oct 11 14:03:22 host sshd[1234]: message` -> parsed event with time."""
    m = re.match(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<prog>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$",
        line,
    )
    if not m:
        return None
    prog = m.group("prog")
    parsed = parse_auth_message(prog, m.group("msg"))
    if not parsed:
        return None
    ts = _syslog_timestamp(m.group("month"), int(m.group("day")), m.group("time"), year)
    parsed["timestamp"] = ts
    parsed["host"] = m.group("host")
    if m.group("pid"):
        parsed["pid"] = int(m.group("pid"))
    return parsed


def _syslog_timestamp(month: str, day: int, time_s: str, year: Optional[int]) -> Optional[float]:
    if year is None:
        year = datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {month} {day} {time_s}", "%Y %b %d %H:%M:%S")
        return dt.timestamp()
    except ValueError:
        return None


class AuthCollector(CollectorBase):
    name = "auth"

    def __init__(self, emit, settings):
        super().__init__(emit, settings)
        cfg = settings.honeytrace.auth
        self.cfg = cfg
        self.source = cfg.source

        if not cfg.enabled:
            self.status = STATUS_DISABLED
            self.status_detail = "auth collector disabled"
            return
        if self.source == "auto":
            self.source = "journal" if shutil.which("journalctl") else "file"
        if os.name != "posix":
            self.status = STATUS_UNAVAILABLE
            self.status_detail = "authentication telemetry requires Linux"
            return
        if self.source == "journal" and not shutil.which("journalctl"):
            self.status = STATUS_UNAVAILABLE
            self.status_detail = "journalctl not found"
            return
        if self.source == "file" and not Path(cfg.auth_log).exists():
            self.status = STATUS_UNAVAILABLE
            self.status_detail = f"{cfg.auth_log} not present; install rsyslog or use journal source"
            return
        self.status = STATUS_OK

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        if self.status != STATUS_OK:
            self.emit_gap(f"auth sensor unavailable: {self.status_detail}")
            return
        try:
            if self.source == "journal":
                self._run_journal()
            else:
                self._run_file()
        except Exception as exc:
            self.status = STATUS_ERROR
            self.status_detail = str(exc)

    def _run_journal(self) -> None:
        cmd = ["journalctl", "-f", "-o", "json", "-n", "0"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        assert proc.stdout is not None
        try:
            for raw in iter(proc.stdout.readline, b""):
                if self.stopping:
                    break
                line = raw.decode("utf-8", "surrogateescape").strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._handle_journal_entry(entry)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    def _handle_journal_entry(self, entry: Dict[str, Any]) -> None:
        prog = entry.get("_COMM") or entry.get("SYSLOG_IDENTIFIER") or "unknown"
        message = entry.get("MESSAGE", "")
        parsed = parse_auth_message(str(prog), str(message))
        if not parsed:
            return
        ts = None
        rt = entry.get("__REALTIME_TIMESTAMP")
        if rt:
            try:
                ts = int(rt) / 1_000_000.0
            except (TypeError, ValueError):
                ts = None
        self._emit_parsed(parsed, ts, journal_cursor=entry.get("__CURSOR"))

    def _run_file(self) -> None:
        path = Path(self.cfg.auth_log)
        inode = None
        fh = None
        seen_lines: Dict[str, int] = {}
        try:
            fh = path.open("r", encoding="utf-8", errors="surrogateescape")
            inode = path.stat().st_ino
            fh.seek(0, os.SEEK_END)
            while not self.stopping:
                try:
                    if path.stat().st_ino != inode:
                        fh.close()
                        fh = path.open("r", encoding="utf-8", errors="surrogateescape")
                        inode = path.stat().st_ino
                        self.emit_gap("auth.log rotated; re-tailing")
                except OSError:
                    pass
                line = fh.readline()
                if not line:
                    if not self.sleep(0.5):
                        break
                    continue
                parsed = parse_auth_log_line(line.rstrip("\n"))
                if not parsed:
                    continue
                # Duplicate suppression across short re-reads.
                key = f"{parsed.get('timestamp')}|{parsed['event_type']}|{parsed.get('actor')}"
                if seen_lines.get(key, 0) >= 1:
                    continue
                seen_lines[key] = 1
                if len(seen_lines) > 4096:
                    seen_lines.clear()
                self._emit_parsed(parsed, parsed.get("timestamp"))
        finally:
            if fh:
                fh.close()

    def _emit_parsed(self, parsed: Dict[str, Any], ts: Any, journal_cursor: Optional[str] = None) -> None:
        details: Dict[str, Any] = {"service": parsed.get("service")}
        if parsed.get("command"):
            details["command"] = parsed["command"]
        if journal_cursor:
            details["journal_cursor"] = journal_cursor
        if parsed.get("session_hint"):
            details["logind_session"] = parsed["session_hint"]
        self.emit(
            {
                "event_type": parsed["event_type"],
                "timestamp": ts,
                "actor": parsed.get("actor"),
                "details": details,
                "observation": "observed",
                "confidence": 0.85,
            }
        )

    # ------------------------------------------------------------------ #

    def replay_lines(self, lines: List[str], year: Optional[int] = None) -> List[Dict[str, Any]]:
        """Test/replay helper: parse raw auth.log lines without running."""
        out = []
        for line in lines:
            parsed = parse_auth_log_line(line, year=year)
            if parsed:
                out.append(parsed)
        return out
