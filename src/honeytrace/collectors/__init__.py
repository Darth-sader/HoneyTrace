"""Collectors observe the OS and emit raw event dicts. Nothing else.

Contract for every collector:

* Emit raw dicts (normalizer builds Event models) via ``self.emit()``.
* NEVER block, mutate system state, or write reports.
* Report status honestly: ok | degraded | error | unavailable | disabled.
  "unavailable" (e.g. no auditd, no root) is a coverage gap, not a crash.
* Fields that could not be observed stay absent - never zero, never guessed.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Optional

from honeytrace.models.events import utc_now_iso

STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"
STATUS_ERROR = "error"
STATUS_UNAVAILABLE = "unavailable"
STATUS_DISABLED = "disabled"


class CollectorBase:
    """Threaded collector skeleton with health bookkeeping."""

    name = "base"

    def __init__(self, emit: Callable[[Dict[str, Any]], None], config=None):
        self._emit_raw = emit
        self.config = config
        self.status = STATUS_DISABLED
        self.status_detail: str = ""
        self.last_event_utc: Optional[str] = None
        self.events_emitted = 0
        self.errors = 0
        self.dropped = 0
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle ----------------------------------------------------------- #

    def start(self) -> None:
        if self.status == STATUS_DISABLED:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._safe_run, name=f"honeytrace-{self.name}", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _safe_run(self) -> None:
        try:
            self.run()
        except Exception as exc:  # a collector must never kill the daemon
            self.status = STATUS_ERROR
            self.status_detail = f"{type(exc).__name__}: {exc}"
            self.errors += 1

    def run(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def sleep(self, seconds: float) -> bool:
        """Interruptible sleep. Returns False when stopping."""
        return not self._stop_event.wait(seconds)

    @property
    def stopping(self) -> bool:
        return self._stop_event.is_set()

    # -- emitting ------------------------------------------------------------ #

    def emit(self, raw: Dict[str, Any]) -> None:
        raw.setdefault("source", self.name)
        self.events_emitted += 1
        self.last_event_utc = utc_now_iso()
        self._emit_raw(raw)

    def emit_gap(self, reason: str) -> None:
        """Record a coverage gap as a first-class event."""
        self.emit(
            {
                "event_type": "health.gap",
                "source": self.name,
                "details": {"gap": reason},
                "observation": "observed",
                "confidence": 1.0,
            }
        )

    # -- health -------------------------------------------------------------- #

    def health(self) -> Dict[str, Any]:
        return {
            "collector": self.name,
            "status": self.status,
            "detail": self.status_detail,
            "events_emitted": self.events_emitted,
            "errors": self.errors,
            "dropped": self.dropped,
            "last_event_utc": self.last_event_utc,
            "alive": bool(self._thread and self._thread.is_alive()),
        }


# FilesystemCollector lives in its own module (inotify is Linux-specific);
# re-export it so `from honeytrace.collectors import FilesystemCollector` works.
from honeytrace.collectors.filesystem import FilesystemCollector  # noqa: E402,F401

__all__ = [
    "CollectorBase",
    "FilesystemCollector",
    "STATUS_OK",
    "STATUS_DEGRADED",
    "STATUS_ERROR",
    "STATUS_UNAVAILABLE",
    "STATUS_DISABLED",
]
