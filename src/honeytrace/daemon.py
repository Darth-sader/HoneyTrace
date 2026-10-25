"""Daemon: application lifecycle, collector supervision and the pipeline.

Wiring (one direction, no collector ever calls another collector):

    collectors --raw--> pipeline queue --> normalizer --> journal (evidence)
                                              |
                                              v
                                     rules engine --> incident manager
                                                          |
                                                    response engine
                                                          |
                                                    notifications

Shutdown order matters: collectors stop first (no new input), then the
pipeline drains, then the journal flushes and closes, then the lock is
released. Emergency-off (response engine) is separate and runs BEFORE any
of this when invoked - it stops responses, not evidence.
"""

from __future__ import annotations

import logging
import os
import queue
import signal
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace import __version__
from honeytrace.collectors import (
    CollectorBase,
    FilesystemCollector,
)
from honeytrace.collectors.audit import AuditCollector
from honeytrace.collectors.auth import AuthCollector
from honeytrace.collectors.canary import CanaryCollector
from honeytrace.collectors.network import NetworkCollector
from honeytrace.collectors.pcap import PcapCollector
from honeytrace.collectors.process import ProcessCollector
from honeytrace.collectors.session import SessionCollector
from honeytrace.config import Settings
from honeytrace.deception.inventory import DecoyInventory
from honeytrace.deception.tokens import TokenRegistry
from honeytrace.deception.workspace import DeceptionWorkspace
from honeytrace.engine.correlate import SessionTracker
from honeytrace.engine.incidents import IncidentManager
from honeytrace.engine.normalize import Normalizer
from honeytrace.engine.response import ArmingState, ResponseEngine
from honeytrace.engine.rules import RuleEngine
from honeytrace.evidence.journal import JournalWriter
from honeytrace.evidence.manifest import ArtifactManifest
from honeytrace.health import HealthMonitor

op_log = logging.getLogger("honeytrace.daemon")


class InstanceLock:
    """Single-instance guarantee via O_EXCL pid file + stale detection."""

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "honeytrace.pid"

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            pid = self._read_pid()
            if pid and self._alive(pid):
                return False
            op_log.warning("removing stale pid file (pid %s)", pid)
            self.path.unlink(missing_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w") as fh:
                fh.write(str(os.getpid()))
            return True
        except FileExistsError:
            return False

    def release(self) -> None:
        try:
            if self.path.exists() and self._read_pid() == os.getpid():
                self.path.unlink()
        except OSError:
            pass

    def _read_pid(self) -> Optional[int]:
        try:
            return int(self.path.read_text().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def _alive(pid: int) -> bool:
        if os.name != "posix":
            return False
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True


class HoneytraceDaemon:
    def __init__(self, settings: Settings, foreground: bool = True):
        self.settings = settings
        self.data_dir = settings.data_dir
        self.state_dir = self.data_dir / "state"
        self.lock = InstanceLock(self.state_dir)
        self.foreground = foreground

        self._stop_event = threading.Event()
        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=20000)
        self._workers: List[threading.Thread] = []
        self._dropped_by_pipeline = 0

        # --- evidence ------------------------------------------------------
        self.journal = JournalWriter(
            self.data_dir / "events",
            key_path=self.state_dir / "checkpoint.key",
            max_segment_bytes=settings.retention.journal.max_segment_mb * 1024 * 1024,
            max_segments=settings.retention.journal.max_segments,
            checkpoint_every=settings.retention.journal.checkpoint_every,
        )
        self.manifest = ArtifactManifest(self.data_dir / "manifests")

        # --- engine ---------------------------------------------------------
        self.session_tracker = SessionTracker()
        self.sensor_status: Dict[str, str] = {}
        self.normalizer = Normalizer(settings.honeytrace.detection.dedup_window_seconds)
        self.rules_engine = RuleEngine(settings.rules, sensor_status=self.sensor_status)
        self.incidents = IncidentManager(
            self.data_dir / "incidents",
            expected_sensors=["filesystem", "audit", "auth", "process", "network"],
            incident_gap_seconds=settings.honeytrace.detection.incident_gap_seconds,
            session_tracker=self.session_tracker,
        )
        self.arming = ArmingState(self.state_dir)
        self.response = ResponseEngine(settings, self.arming, journal=self.journal)

        # --- deception -------------------------------------------------------
        self.registry = TokenRegistry(
            callback_url_base=f"http://{settings.honeytrace.network.canary_host}:{settings.honeytrace.network.canary_port}/beacon"
        )
        self.inventory = DecoyInventory(self.data_dir)
        self.workspace = DeceptionWorkspace(settings, self.inventory, self.registry)

        # --- notifications (optional GUI) ------------------------------------
        self.notifier = self._build_notifier()

        # --- collectors --------------------------------------------------------
        self.collectors: List[CollectorBase] = self._build_collectors()
        for c in self.collectors:
            self.sensor_status[c.name] = c.status

        self.health = HealthMonitor(
            settings, self.journal, self.incidents, self.collectors,
            emit=self._safe_emit, op_log=op_log,
        )

    # ------------------------------------------------------------------ #
    # Construction helpers
    # ------------------------------------------------------------------ #

    def _build_notifier(self):
        try:
            from honeytrace.notifications.desktop import IncidentNotifier

            return IncidentNotifier(self.incidents)
        except Exception as exc:  # headless systems still work
            op_log.info("desktop notifications unavailable: %s", exc)
            return None

    def _build_collectors(self) -> List[CollectorBase]:
        s = self.settings
        cfg = s.honeytrace
        collectors: List[CollectorBase] = []

        fs = FilesystemCollector(self._safe_emit, s)
        fs.attach_inventory(self.inventory)
        collectors.append(fs)
        collectors.append(AuditCollector(self._safe_emit, s))
        auth = AuthCollector(self._safe_emit, s)
        collectors.append(auth)
        collectors.append(ProcessCollector(self._safe_emit, s))
        net = NetworkCollector(self._safe_emit, s)
        collectors.append(net)
        collectors.append(PcapCollector(self._safe_emit, s, manifest=self.manifest))
        canary = CanaryCollector(self._safe_emit, s, registry=self.registry)
        collectors.append(canary)
        session = SessionCollector(self._safe_emit, s, manifest=self.manifest,
                                   session_tracker=self.session_tracker)
        collectors.append(session)
        self._auth_collector = auth
        return collectors

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        if not self.lock.acquire():
            op_log.error("another HoneyTrace instance is running (pid file %s)", self.lock.path)
            return False

        problems = self.settings.validate()
        if problems:
            for p in problems:
                op_log.warning("config problem: %s", p)
            self.arming.set_state("degraded")
        else:
            self.arming.set_state("armed" if self.arming.body.get("state") == "armed" else "armed")

        self.workspace.set_boundaries(self.settings.decoys_dir, self.settings.monitored_paths())

        self.journal.start()
        for worker in range(2):
            t = threading.Thread(target=self._pipeline, name=f"honeytrace-pipeline-{worker}", daemon=True)
            t.start()
            self._workers.append(t)

        for c in self.collectors:
            if c.status != "disabled":
                c.start()
            self.sensor_status[c.name] = c.status
            op_log.info("collector %-10s status=%s %s", c.name, c.status, c.status_detail)

        self.health.start()
        self.arming.set_state("armed")
        self.journal.append(
            {
                "event_type": "daemon.start",
                "source": "health",
                "details": {
                    "version": __version__,
                    "mode": self.settings.honeytrace.mode,
                    "collectors": {c.name: c.status for c in self.collectors},
                    "pid": os.getpid(),
                },
                "observation": "observed",
                "confidence": 1.0,
            }
        )
        op_log.info(
            "HoneyTrace %s started in %s mode with %d collectors",
            __version__, self.settings.honeytrace.mode, len(self.collectors),
        )
        return True

    def run_forever(self) -> None:
        if not self.start():
            raise SystemExit(1)
        stop_signals = (signal.SIGINT, signal.SIGTERM)
        for sig in stop_signals:
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass  # not the main thread / unsupported
        try:
            while not self._stop_event.is_set():
                time.sleep(0.5)
        finally:
            self.stop()

    def _signal_handler(self, sig, frame) -> None:  # noqa: ANN001
        op_log.info("received signal %s, shutting down cleanly", sig)
        self._stop_event.set()

    def stop(self) -> None:
        op_log.info("stopping collectors...")
        for c in self.collectors:
            try:
                c.stop(timeout=5)
            except Exception as exc:
                op_log.warning("collector %s stop error: %s", c.name, exc)
            self.sensor_status[c.name] = c.status

        self.health.stop()
        self.arming.set_state("stopping")

        # Drain the pipeline queue, then close the journal (flush + checkpoint).
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not self._queue.empty():
            time.sleep(0.05)
        self.journal.append(
            {
                "event_type": "daemon.stop",
                "source": "health",
                "details": {
                    "reason": "operator requested shutdown",
                    "dropped_pipeline": self._dropped_by_pipeline,
                },
                "observation": "observed",
                "confidence": 1.0,
            }
        )
        self.journal.close(timeout=8)
        self.arming.set_state("armed" if self.arming.body.get("state") == "armed" else "disarmed")
        self.lock.release()
        op_log.info("shutdown complete; evidence preserved at %s", self.data_dir / "events")

    # ------------------------------------------------------------------ #
    # Pipeline
    # ------------------------------------------------------------------ #

    def _safe_emit(self, raw: Dict[str, Any]) -> None:
        """Collectors call this. Non-blocking; drops with counter when full."""
        try:
            self._queue.put_nowait(raw)
        except queue.Full:
            self._dropped_by_pipeline += 1

    def _pipeline(self) -> None:
        while True:
            try:
                raw = self._queue.get(timeout=0.5)
            except queue.Empty:
                if self._stop_event.is_set():
                    break
                continue
            try:
                self._process(raw)
            except Exception as exc:
                op_log.exception("pipeline error: %s", exc)
            finally:
                self._queue.task_done()

    def _process(self, raw: Dict[str, Any]) -> None:
        event = self.normalizer.normalize(raw)
        if event is None:
            return

        # Journal first: raw evidence survives even if the engine crashes.
        self.journal.append(event.to_dict())

        # Session state feeds off auth events.
        if event.source == "auth" or (event.event_type or "").startswith("auth."):
            self.session_tracker.observe(event)

        # Detection.
        matches = self.rules_engine.on_event(event)
        if matches:
            for m in matches:
                event.rule_matches.append(m.rule_id)
            touched = self.incidents.on_matches(
                matches, event=event, sensor_status=self.sensor_status
            )
            for incident in touched:
                for match in incident.rule_matches:
                    if match.rule_id not in [m.rule_id for m in matches]:
                        continue
                    record = self.response.evaluate(match, incident, event.to_dict())
                    if record and self.incidents.get(incident.incident_id):
                        self.incidents.add_response_record(
                            incident.incident_id, record.model_dump(mode="json")
                        )
                if self.notifier:
                    self.notifier.notify_incident(incident)

    # ------------------------------------------------------------------ #

    def status_snapshot(self) -> Dict[str, Any]:
        return {
            "version": __version__,
            "mode": self.arming.mode,
            "state": self.arming.body.get("state"),
            "containment_armed": self.arming.containment_armed,
            "collectors": [c.health() for c in self.collectors],
            "journal": self.journal.stats(),
            "incidents": {
                "unread": self.incidents.unread_count(),
                "active": self.incidents.active_count(),
                "sessions": self.incidents.session_tracker and len(
                    self.incidents.session_tracker.active_sessions()
                ),
            },
        }
