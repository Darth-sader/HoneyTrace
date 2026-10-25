"""Linux Audit collector: tail and parse auditd records for attribution.

Why this exists: inotify cannot attribute file access to a process. The
audit subsystem can. This collector tails /var/log/audit/audit.log, groups
records by audit event id (serial), and emits:

    exec.command     - EXECVE records (the preferred command telemetry)
    file.open/delete/rename - SYSCALL+PATH records for monitored paths
    auth.login_success / auth.login_failure - USER_AUTH / USER_LOGIN
    auth.session_open / auth.session_close - USER_START / USER_END
    priv.escalation  - sudo/su CRED_ACQ or auid!=uid transitions

The parser is fully unit-testable without Linux (see tests/fixtures).

Filtering: records are used when they carry the configured audit key, OR
when their paths fall under monitored roots, OR when auid matches the lab
user. Everything else is ignored to keep the journal bounded.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from honeytrace.collectors import (
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    CollectorBase,
)

HEADER_RE = re.compile(r"type=(\S+)\s+msg=audit\((\d+)\.(\d+):(\d+)\):\s*")
KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')
HEX_KEYS = {"name", "exe", "cwd", "proctitle", "cmd"}

# Syscall numbers (x86_64) we translate into normalized file events.
SYSCALL_MAP = {
    "2": "file.open",        # open
    "257": "file.open",      # openat
    "87": "file.delete",     # unlink
    "263": "file.delete",    # unlinkat
    "82": "file.rename",     # rename
    "316": "file.rename",    # renameat2
    "1": "file.modify",      # write
}


def decode_field(key: str, value: str) -> str:
    """Audit log values are quoted, plain, or hex-encoded."""
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if key in HEX_KEYS and re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", value or ""):
        try:
            return bytes.fromhex(value).decode("utf-8", "surrogateescape").rstrip("\x00")
        except ValueError:
            return value
    return value


def parse_audit_line(line: str) -> Optional[Tuple[str, float, int, Dict[str, str]]]:
    """One raw audit line -> (type, epoch, serial, fields). None if not audit."""
    m = HEADER_RE.search(line)
    if not m:
        return None
    rtype, epoch_s, ms_s, serial_s = m.groups()
    fields: Dict[str, str] = {}
    tail = line[m.end():]
    for key, raw in KV_RE.findall(tail):
        fields[key] = decode_field(key, raw.strip('"'))
    epoch = int(epoch_s) + int(ms_s) / 1000.0
    return rtype, epoch, int(serial_s), fields


class AuditCollector(CollectorBase):
    name = "audit"

    def __init__(self, emit, settings, monitored_roots: Optional[List[str]] = None):
        super().__init__(emit, settings)
        self.settings = settings
        cfg = settings.honeytrace.audit
        self.log_path = Path(cfg.log_file)
        self.key = cfg.key
        self.monitored_roots = monitored_roots or [str(p) for p in settings.monitored_paths()]
        self.lab_uid = self._resolve_lab_uid()

        if not cfg.enabled:
            self.status = STATUS_DISABLED
            self.status_detail = "audit collector disabled in configuration"
        elif os.name != "posix" or not self.log_path.exists():
            self.status = STATUS_UNAVAILABLE
            self.status_detail = f"audit log not readable at {self.log_path} (coverage gap: file attribution degraded)"
        elif not os.access(self.log_path, os.R_OK):
            self.status = STATUS_UNAVAILABLE
            self.status_detail = f"no read permission on {self.log_path}; add CAP_AUDIT_READ or adm group"
        else:
            self.status = STATUS_OK

    @staticmethod
    def _resolve_lab_uid() -> Optional[int]:
        try:
            import pwd

            return pwd.getpwuid(os.getuid()).pw_uid if os.getuid() == 0 else None
        except (ImportError, KeyError):
            return None

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        if self.status != STATUS_OK:
            # Emit one gap so the coverage dashboard knows why attribution
            # will be weak, then stay idle.
            self.emit_gap(f"audit sensor unavailable: {self.status_detail}")
            return
        self.status = STATUS_OK
        inode = None
        fh = None
        partial = b""
        buffer: Dict[int, Dict[str, Any]] = {}
        try:
            fh = self.log_path.open("rb")
            inode = self.log_path.stat().st_ino
            fh.seek(0, os.SEEK_END)
            while not self.stopping:
                # Rotation detection.
                try:
                    if self.log_path.stat().st_ino != inode:
                        fh.close()
                        fh = self.log_path.open("rb")
                        inode = self.log_path.stat().st_ino
                        self.emit_gap("audit log rotated; re-tailing from start")
                except OSError:
                    pass
                chunk = fh.readline()
                if not chunk:
                    if buffer:
                        self._flush_all(buffer)
                    if not self.sleep(0.5):
                        break
                    continue
                self._process_line(chunk.decode("utf-8", "surrogateescape"), buffer)
        finally:
            if fh:
                fh.close()

    def _process_line(self, line: str, buffer: Dict[int, Dict[str, Any]]) -> None:
        parsed = parse_audit_line(line)
        if not parsed:
            return
        rtype, epoch, serial, fields = parsed
        # Audit groups are contiguous: when a NEW serial starts, every older
        # serial in the buffer is complete and can be dispatched (this is
        # what lets a PATH record that arrives after its SYSCALL contribute).
        self._flush_older(buffer, serial)
        rec = buffer.setdefault(serial, {"epoch": epoch, "records": {}})
        rec["records"][rtype] = fields
        rec["epoch"] = max(rec["epoch"], epoch)
        if len(buffer) > 512:
            self._flush_older(buffer, serial + 1)

    def _flush_older(self, buffer: Dict[int, Dict[str, Any]], serial: int) -> None:
        for older in sorted(s for s in buffer if s < serial):
            rec = buffer.pop(older)
            self._dispatch(rec, older)

    def _flush_all(self, buffer: Dict[int, Dict[str, Any]]) -> None:
        for serial in sorted(buffer):
            rec = buffer.pop(serial)
            self._dispatch(rec, serial)

    def _dispatch(self, rec: Dict[str, Any], serial: int) -> None:
        records = rec["records"]
        if "SYSCALL" in records:
            self._handle_syscall(rec, serial)
        if "EXECVE" in records:
            self._handle_execve(rec, serial)
        for rtype in ("USER_AUTH", "USER_LOGIN", "USER_START", "USER_END", "CRED_ACQ"):
            if rtype in records:
                self._handle_user_event(rtype, rec, serial)

    # ------------------------------------------------------------------ #

    def _relevant(self, fields: Dict[str, str]) -> bool:
        if fields.get("key") == self.key:
            return True
        name = fields.get("name", "")
        for root in self.monitored_roots:
            if name.startswith(root):
                return True
        if self.lab_uid is not None and fields.get("auid") == str(self.lab_uid):
            return True
        return False

    def _handle_syscall(self, rec: Dict[str, Any], serial: int) -> None:
        fields = rec["records"].get("SYSCALL", {})
        if not self._relevant(fields) and not self._relevant(rec["records"].get("PATH", {})):
            return
        syscall = fields.get("syscall", "")
        event_type = SYSCALL_MAP.get(syscall)
        if event_type is None:
            return
        if fields.get("success") == "no":
            return
        path = rec["records"].get("PATH", {}).get("name") or fields.get("name") or ""
        if not path:
            return
        ses = fields.get("ses")
        self.emit(
            {
                "event_type": event_type,
                "source": self.name,
                "timestamp": rec["epoch"],
                "actor": {
                    "uid": _int_or_none(fields.get("auid")),
                    "username": None,
                    "session_id": f"audit-ses-{ses}" if ses and ses != "unset" else None,
                    "tty": fields.get("tty") if fields.get("tty") not in ("?", None) else None,
                    "attribution": "observed",
                },
                "process": {
                    "pid": _int_or_none(fields.get("pid")),
                    "ppid": _int_or_none(fields.get("ppid")),
                    "exe": fields.get("exe"),
                    "cwd": rec["records"].get("CWD", {}).get("cwd"),
                    "source": "linux-audit",
                },
                "target": {"path": path},
                "details": {
                    "audit_serial": serial,
                    "comm": fields.get("comm"),
                    "exit": fields.get("exit"),
                },
                "observation": "observed",
                "confidence": 0.9,
            }
        )

    def _handle_execve(self, rec: Dict[str, Any], serial: int) -> None:
        fields = rec["records"].get("SYSCALL", {})
        execve = rec["records"].get("EXECVE", {})
        if not self._relevant(fields):
            return
        argv = []
        i = 0
        while f"a{i}" in execve:
            argv.append(execve[f"a{i}"])
            i += 1
        if not argv:
            proctitle = execve.get("proctitle") or fields.get("proctitle")
            if proctitle:
                argv = proctitle.split("\x00") if "\x00" in proctitle else [proctitle]
        exe = fields.get("exe") or (argv[0] if argv else None)
        ses = fields.get("ses")
        self.emit(
            {
                "event_type": "exec.command",
                "source": self.name,
                "timestamp": rec["epoch"],
                "actor": {
                    "uid": _int_or_none(fields.get("auid")),
                    "session_id": f"audit-ses-{ses}" if ses and ses != "unset" else None,
                    "tty": fields.get("tty") if fields.get("tty") not in ("?", None) else None,
                    "attribution": "observed",
                },
                "process": {
                    "pid": _int_or_none(fields.get("pid")),
                    "ppid": _int_or_none(fields.get("ppid")),
                    "exe": exe,
                    "cmdline": argv,
                    "source": "linux-audit",
                },
                "details": {
                    "audit_serial": serial,
                    "comm": fields.get("comm"),
                    "argv": argv,
                },
                "observation": "observed",
                "confidence": 0.9,
            }
        )

    def _handle_user_event(self, rtype: str, rec: Dict[str, Any], serial: int) -> None:
        fields = rec["records"].get(rtype, {})
        if not self._relevant(fields) and fields.get("acct") is None and fields.get("addr") is None:
            return
        success = fields.get("res", fields.get("result", "")) in ("success", "1", "yes")
        acct = fields.get("acct")
        addr = fields.get("addr")
        ses = fields.get("ses")
        uid = _int_or_none(fields.get("uid"))
        auid = _int_or_none(fields.get("auid"))
        mapping = {
            "USER_AUTH": "auth.login_success" if success else "auth.login_failure",
            "USER_LOGIN": "auth.login_success" if success else "auth.login_failure",
            "USER_START": "auth.session_open",
            "USER_END": "auth.session_close",
        }
        event_type = mapping.get(rtype)
        if event_type:
            self.emit(
                {
                    "event_type": event_type,
                    "source": self.name,
                    "timestamp": rec["epoch"],
                    "actor": {
                        "uid": auid if auid is not None else uid,
                        "username": acct,
                        "source_ip": addr if addr and addr != "?" else None,
                        "session_id": f"audit-ses-{ses}" if ses and ses != "unset" else None,
                        "attribution": "observed",
                    },
                    "details": {"audit_serial": serial, "service": fields.get("acct_type", "audit")},
                    "observation": "observed",
                    "confidence": 0.9,
                }
            )
        if rtype == "CRED_ACQ" and success:
            # sudo/su acquisition: privilege change indicator.
            self.emit(
                {
                    "event_type": "priv.escalation",
                    "source": self.name,
                    "timestamp": rec["epoch"],
                    "actor": {
                        "uid": auid,
                        "username": acct or fields.get("subj"),
                        "session_id": f"audit-ses-{ses}" if ses and ses != "unset" else None,
                        "attribution": "observed",
                    },
                    "process": {"exe": fields.get("exe"), "source": "linux-audit"},
                    "details": {"audit_serial": serial, "mechanism": "cred_acq"},
                    "observation": "observed",
                    "confidence": 0.85,
                }
            )

    # ------------------------------------------------------------------ #

    def parse_file(self, path: Path) -> List[Dict[str, Any]]:
        """Replay a whole audit log file (used by tests and demo replay)."""
        buffer: Dict[int, Dict[str, Any]] = {}
        with Path(path).open("r", encoding="utf-8", errors="surrogateescape") as fh:
            for line in fh:
                self._process_line(line.rstrip("\n"), buffer)
        self._flush_all(buffer)
        return []


def _int_or_none(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
