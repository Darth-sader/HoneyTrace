"""Health and diagnostics monitor.

Tracks per-collector health, evidence-journal stats (queue depth, dropped
events, storage errors), incident counters, and disk usage of the evidence
directory. Writes data/health.json for `honeytrace status` and the
dashboard, and raises health.gap / health alert events when something
degrades. This is HoneyTrace's own diagnostics - it never writes evidence.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from honeytrace.models.events import utc_now_iso


class HealthMonitor:
    def __init__(
        self,
        settings,
        journal,
        incident_manager,
        collectors: List[Any],
        emit: Optional[Callable[[Dict[str, Any]], None]] = None,
        op_log=None,
    ):
        self.settings = settings
        self.journal = journal
        self.incidents = incident_manager
        self.collectors = collectors
        self.emit = emit
        self.op_log = op_log
        self.interval = settings.honeytrace.health.check_interval_seconds
        self.low_disk_percent = settings.honeytrace.health.low_disk_warn_percent
        self.queue_warn = settings.honeytrace.health.queue_warn_depth
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_report: Dict[str, Any] = {}
        self.alerts: List[Dict[str, Any]] = []

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="honeytrace-health", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.check()
            except Exception as exc:  # diagnostics must never kill the daemon
                if self.op_log:
                    self.op_log.warning("health check failed: %s", exc)

    # ------------------------------------------------------------------ #

    def check(self) -> Dict[str, Any]:
        report: Dict[str, Any] = {
            "timestamp_utc": utc_now_iso(),
            "collectors": [c.health() for c in self.collectors],
            "journal": self.journal.stats() if self.journal else {},
            "incidents": {
                "unread": self.incidents.unread_count(),
                "active": self.incidents.active_count(),
            },
            "disk": self.disk_usage(self.settings.data_dir),
            "alerts": list(self.alerts[-20:]),
        }
        self.last_report = report
        self._write_health_file(report)
        self._evaluate_alerts(report)
        return report

    @staticmethod
    def disk_usage(path: Path) -> Dict[str, Any]:
        usage: Dict[str, Any] = {"path": str(path), "used_mb": None, "free_mb": None, "percent": None}
        try:
            total, used, free = shutil.disk_usage(path)
            usage.update(
                {
                    "total_mb": int(total // (1024 * 1024)),
                    "used_mb": int(used // (1024 * 1024)),
                    "free_mb": int(free // (1024 * 1024)),
                    "percent": round(used / total * 100, 1) if total else None,
                }
            )
        except OSError:
            pass
        return usage

    def _write_health_file(self, report: Dict[str, Any]) -> None:
        path = self.settings.data_dir / "health.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            pass

    def _evaluate_alerts(self, report: Dict[str, Any]) -> None:
        new_alerts: List[str] = []

        for c in report["collectors"]:
            if c["status"] in ("error",) or (c["status"] == "ok" and not c["alive"]):
                msg = f"collector {c['collector']} unhealthy: {c['status']} {c.get('detail', '')}"
                new_alerts.append(msg)

        journal = report["journal"]
        if journal.get("queue_depth", 0) > self.queue_warn:
            new_alerts.append(f"journal queue depth {journal['queue_depth']} exceeds {self.queue_warn}")
        if journal.get("dropped_events", 0) > 0:
            new_alerts.append(f"{journal['dropped_events']} events dropped by the journal")
        if journal.get("storage_alert"):
            new_alerts.append(str(journal["storage_alert"]))

        disk = report["disk"]
        if disk.get("percent") is not None and disk["percent"] >= self.low_disk_percent:
            new_alerts.append(f"evidence disk usage at {disk['percent']}% (warn at {self.low_disk_percent}%)")
        quota_mb = self.settings.retention.quota.data_dir_max_mb
        if disk.get("used_mb") is not None and disk["used_mb"] > quota_mb:
            new_alerts.append(f"data directory exceeds quota ({disk['used_mb']} MB > {quota_mb} MB)")

        for msg in new_alerts:
            if any(a["message"] == msg for a in self.alerts[-50:]):
                continue
            alert = {"timestamp_utc": utc_now_iso(), "message": msg}
            self.alerts.append(alert)
            if self.op_log:
                self.op_log.warning("HEALTH: %s", msg)
            if self.emit:
                self.emit(
                    {
                        "event_type": "health.alert",
                        "source": "health",
                        "details": {"alert": msg},
                        "observation": "observed",
                        "confidence": 1.0,
                    }
                )
