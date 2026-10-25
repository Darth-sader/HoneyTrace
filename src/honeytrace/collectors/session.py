"""Session collector: session state, scoped recording artifacts and tlog.

Responsibilities (deliberately narrow and honest):

1. Maintain the SessionTracker state machine from auth events so incidents
   and profiles can reference session context.
2. Watch the configured session-artifact directory (tlog output). When a
   recording file appears or grows closed, it is hashed into the artifact
   manifest and referenced in the journal. HoneyTrace does NOT do raw TTY
   polling - keystroke capture is delegated to a real recorder (tlog) that
   the operator configures for the dedicated lab account only.
3. Report tlog availability so `doctor` and the coverage view can say
   whether scoped terminal recording is possible.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from honeytrace.collectors import STATUS_DISABLED, STATUS_OK, STATUS_UNAVAILABLE, CollectorBase
from honeytrace.engine.correlate import SessionTracker


class SessionCollector(CollectorBase):
    name = "session"

    def __init__(self, emit, settings, manifest=None, session_tracker: Optional[SessionTracker] = None):
        super().__init__(emit, settings)
        self.settings = settings
        self.manifest = manifest
        self.tracker = session_tracker or SessionTracker()
        self.sessions_dir = settings.data_dir / "sessions"
        self.tlog_available = bool(shutil.which("tlog-rec-session"))
        self._known: Dict[str, int] = {}

        self.status = STATUS_OK
        self.status_detail = (
            "tlog available - scoped recording possible"
            if self.tlog_available
            else "tlog not installed - scoped terminal recording unavailable (documented gap)"
        )

    # ------------------------------------------------------------------ #

    def observe_auth(self, raw_event: Dict[str, Any]) -> None:
        """Called by the daemon for every auth.* event to maintain state."""
        from honeytrace.engine.normalize import Normalizer

        normalized = Normalizer().normalize(raw_event)
        if normalized:
            self.tracker.observe(normalized)

    def active_session_count(self) -> int:
        return len(self.tracker.active_sessions())

    def run(self) -> None:
        if self.status == STATUS_DISABLED:
            return
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        while not self.stopping:
            self._sweep_artifacts()
            self.sleep(10.0)

    def _sweep_artifacts(self) -> None:
        if not self.sessions_dir.is_dir():
            return
        for p in sorted(self.sessions_dir.glob("*")):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            prev = self._known.get(str(p))
            if prev == size:
                continue
            grew = prev is not None and size > prev
            self._known[str(p)] = size
            if size == 0 or (grew and self.stopping):
                continue
            entry = None
            if self.manifest is not None and not grew:
                entry = self.manifest.add(
                    p, "session-recording", self.name,
                    notes="tlog session artifact (operator-configured recorder)",
                )
            # Only record the reference once per file (when first seen).
            if prev is None:
                self.emit(
                    {
                        "event_type": "session.artifact",
                        "target": {"path": str(p)},
                        "details": {
                            "artifact_id": entry["artifact_id"] if entry else None,
                            "size": size,
                            "sha256": entry["sha256"] if entry else None,
                            "recorder": "tlog" if self.tlog_available else "unknown",
                        },
                        "observation": "observed",
                        "confidence": 0.9,
                    }
                )

    def health(self) -> Dict[str, Any]:
        h = super().health()
        h.update(
            {
                "active_sessions": self.active_session_count(),
                "tlog_available": self.tlog_available,
                "session_artifacts": len(self._known),
            }
        )
        return h
