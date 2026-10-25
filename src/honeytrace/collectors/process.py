"""Process collector: lifecycle snapshots via psutil.

Emits process.start / process.exit for NEW processes (identified by
(pid, start_time) so PID reuse cannot alias an old process). Captures the
environment ONLY for allowlisted variables - everything else is dropped
before it ever reaches storage. Denied fields (cwd, exe, fds) are recorded
as absent, never as zero.

Command telemetry preference: audit EXECVE events (audit collector) are the
authoritative command record; this collector provides lifecycle data and a
fallback when auditd is unavailable.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Set, Tuple

from honeytrace.collectors import STATUS_DISABLED, STATUS_ERROR, STATUS_OK, CollectorBase

try:
    import psutil

    PSUTIL_OK = True
except ImportError:  # pragma: no cover
    PSUTIL_OK = False


class ProcessCollector(CollectorBase):
    name = "process"

    def __init__(self, emit, settings):
        super().__init__(emit, settings)
        self.settings = settings
        cfg = settings.honeytrace.process
        self.interval = cfg.scan_interval_seconds
        self.env_allowlist = set(cfg.env_allowlist)
        self._seen: Dict[Tuple[int, float], Dict[str, Any]] = {}
        self._alive: Set[Tuple[int, float]] = set()

        if not cfg.enabled:
            self.status = STATUS_DISABLED
            self.status_detail = "process collector disabled"
        elif not PSUTIL_OK:
            self.status = STATUS_ERROR
            self.status_detail = "psutil not installed"
        else:
            self.status = STATUS_OK

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        if self.status != STATUS_OK:
            self.emit_gap(f"process sensor unavailable: {self.status_detail}")
            return
        while not self.stopping:
            started = time.monotonic()
            self._scan()
            elapsed = time.monotonic() - started
            self.sleep(max(0.1, self.interval - elapsed))

    def _scan(self) -> None:
        current: Set[Tuple[int, float]] = set()
        for proc in psutil.process_iter(["pid", "create_time"]):
            try:
                key = (proc.info["pid"], float(proc.info["create_time"]))
                current.add(key)
                if key not in self._seen:
                    snapshot = self.snapshot(key[0], start_time=key[1])
                    if snapshot is not None:
                        self._seen[key] = snapshot
                        self._emit_start(key, snapshot)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Exits: previously seen keys no longer alive.
        for key in list(self._seen.keys()):
            if key not in current and key not in self._alive:
                snap = self._seen.pop(key)
                self.emit(
                    {
                        "event_type": "process.exit",
                        "timestamp": key[1],
                        "process": {
                            "pid": key[0],
                            "start_time": key[1],
                            "exe": snap.get("exe"),
                            "cmdline": snap.get("cmdline", []),
                            "source": "proc-scan",
                        },
                        "details": {"exit_observed": True},
                        "observation": "observed",
                        "confidence": 0.6,
                    }
                )
        self._alive = current

    def _emit_start(self, key: Tuple[int, float], snap: Dict[str, Any]) -> None:
        actor: Dict[str, Any] = {"attribution": "observed"}
        if snap.get("uid") is not None:
            actor["uid"] = snap["uid"]
        try:
            username = snap.get("username")
            if username:
                actor["username"] = username
        except Exception:
            pass
        env = {}
        if snap.get("_env_full"):
            env = {k: v for k, v in snap["_env_full"].items() if k in self.env_allowlist}
        self.emit(
            {
                "event_type": "process.start",
                "timestamp": key[1],
                "actor": actor,
                "process": {
                    "pid": key[0],
                    "ppid": snap.get("ppid"),
                    "start_time": key[1],
                    "exe": snap.get("exe"),
                    "cmdline": snap.get("cmdline", []),
                    "cwd": snap.get("cwd"),
                    "uid": snap.get("uid"),
                    "gid": snap.get("gid"),
                    "terminal": snap.get("terminal"),
                    "status": snap.get("status"),
                    "source": "proc-scan",
                },
                "details": {
                    "environment_allowlisted": env,
                    "ancestry": self.ancestry(key[0]),
                },
                "observation": "observed",
                "confidence": 0.7,
            }
        )

    # -- snapshot helpers ----------------------------------------------------- #

    def snapshot(self, pid: int, start_time: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Full snapshot of a process. Denied fields are simply absent."""
        try:
            proc = psutil.Process(pid)
            if start_time is not None and abs(proc.create_time() - start_time) > 0.01:
                return None  # PID was reused between scan and snapshot
            snap: Dict[str, Any] = {
                "pid": pid,
                "ppid": proc.ppid(),
                "start_time": proc.create_time(),
                "status": proc.status(),
            }
            for attr, key in (("exe", "exe"), ("cwd", "cwd"), ("terminal", "terminal")):
                try:
                    val = getattr(proc, attr)()
                    if val:
                        snap[key] = val
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError, AttributeError):
                    pass  # attribute missing on this platform = field absent
            try:
                snap["cmdline"] = proc.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                snap["cmdline"] = []
            try:
                snap["uid"] = proc.uids().real
                snap["gid"] = proc.gids().real
                snap["username"] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass  # uid/gid do not exist on some platforms (e.g. Windows)
            try:
                env = proc.environ()
                snap["_env_full"] = env
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass
            return snap
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def ancestry(self, pid: int, max_depth: int = 12) -> list:
        """Parent chain at event time (nearest parent first)."""
        chain = []
        seen = set()
        cur = pid
        for _ in range(max_depth):
            if cur in seen or cur <= 1:
                break
            seen.add(cur)
            try:
                proc = psutil.Process(cur)
                parent = proc.parent()
                if parent is None:
                    break
                try:
                    chain.append([str(parent.pid), parent.exe() or parent.name()])
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    chain.append([str(parent.pid), "unknown"])
                cur = parent.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                break
        return chain

    def resource_snapshot(self, pid: int, start_time: Optional[float] = None) -> Dict[str, Any]:
        """CPU/RSS/threads/FD snapshot when permissions allow. Absent = denied."""
        out: Dict[str, Any] = {"pid": pid}
        try:
            proc = psutil.Process(pid)
            if start_time is not None and abs(proc.create_time() - start_time) > 0.01:
                out["pid_reuse_detected"] = True
                return out
            with proc.oneshot():
                out["cpu_percent"] = proc.cpu_percent(None)
                out["rss_bytes"] = proc.memory_info().rss
                out["num_threads"] = proc.num_threads()
                try:
                    out["num_fds"] = proc.num_fds()
                except (psutil.AccessDenied, AttributeError, OSError):
                    pass
                out["status"] = proc.status()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            out["denied"] = True
        return out

    def health(self) -> Dict[str, Any]:
        h = super().health()
        h["tracked_processes"] = len(self._seen)
        return h
