"""Incident-driven desktop notifications.

Key behavioral change vs the legacy notifier: counters are driven by the
INCIDENT STORE (unread incidents / active incidents / active sessions),
not by raw events. Notification actions open the SPECIFIC incident in the
dashboard. Read/acknowledgement state is persisted by the IncidentManager,
separately from evidence.

pystray/Pillow are optional; headless systems (and systems without a
notification service) get graceful degradation to console messages.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import webbrowser
from typing import Any, Dict, Optional

op_log = logging.getLogger("honeytrace.notify")

try:
    import pystray
    from PIL import Image, ImageDraw

    GUI_OK = True
except ImportError:
    GUI_OK = False


def _tray_image(unread: int):
    color = "red" if unread > 0 else "green"
    image = Image.new("RGB", (64, 64), color="white")
    draw = ImageDraw.Draw(image)
    draw.ellipse([4, 4, 60, 60], fill=color)
    label = str(unread) if 0 < unread < 10 else ("9+" if unread >= 10 else "")
    if label:
        draw.text((32, 32), label, fill="white", anchor="mm")
    return image


class IncidentNotifier:
    """Connects the incident store to notify-send and (optionally) a tray."""

    def __init__(self, incident_manager, dashboard_url: str = "http://127.0.0.1:8443"):
        self.incidents = incident_manager
        self.dashboard_url = dashboard_url.rstrip("/")
        self.icon = None
        self._lock = threading.Lock()
        self._last_seen_ids: set = set()
        self._started = False

    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Start the tray if a desktop session exists; otherwise stay silent."""
        if self._started:
            return
        self._started = True
        if not GUI_OK:
            op_log.info("desktop tray unavailable (pystray/Pillow missing); notify-send still used")
            return
        try:
            self.icon = pystray.Icon(
                "honeytrace",
                _tray_image(self.incidents.unread_count()),
                "HoneyTrace incident monitor",
                menu=self._menu(),
            )
            threading.Thread(target=self.icon.run, daemon=True).start()
        except Exception as exc:
            op_log.info("tray icon failed to start: %s", exc)
            self.icon = None

    def stop(self) -> None:
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
            self.icon = None

    # ------------------------------------------------------------------ #

    def notify_incident(self, incident) -> None:
        """Called by the daemon when an incident is created/updated."""
        if incident.incident_id in self._last_seen_ids:
            self._update_badge()
            return
        self._last_seen_ids.add(incident.incident_id)
        title = f"HoneyTrace {incident.severity.upper()}: {incident.title}"
        body = (
            f"Incident {incident.incident_id}\n"
            f"confidence {incident.confidence:.0%} | {len(incident.event_ids)} events\n"
            f"open: {self.dashboard_url}/incident/{incident.incident_id}"
        )
        self._send(title, body)
        self._update_badge()

    def notify_health(self, message: str) -> None:
        self._send("HoneyTrace health", message)

    def _send(self, title: str, body: str) -> None:
        send = shutil.which("notify-send")
        if not send:
            op_log.info("NOTIFICATION (no notify-send): %s - %s", title, body.replace("\n", " | "))
            return
        # Never block the pipeline on a desktop notification.
        def _fire() -> None:
            try:
                subprocess.run(
                    [send, "-a", "HoneyTrace", "-u", "critical", "-t", "8000", title, body],
                    capture_output=True, timeout=5,
                )
            except Exception as exc:
                op_log.debug("notify-send failed: %s", exc)

        threading.Thread(target=_fire, daemon=True).start()

    def _update_badge(self) -> None:
        if not self.icon:
            return
        try:
            unread = self.incidents.unread_count()
            self.icon.icon = _tray_image(unread)
            self.icon.title = f"HoneyTrace - {unread} unread incident(s)"
            self.icon.menu = self._menu()
        except Exception as exc:
            op_log.debug("badge update failed: %s", exc)

    # -- tray menu (opens the SPECIFIC incident, not the newest log) ---------- #

    def _menu(self):
        if not GUI_OK:
            return None
        items = [
            pystray.MenuItem(
                lambda item: f"Unread incidents: {self.incidents.unread_count()}",
                None, enabled=False,
            ),
            pystray.MenuItem(
                lambda item: f"Active incidents: {self.incidents.active_count()}",
                None, enabled=False,
            ),
            pystray.Menu.SEPARATOR,
        ]
        for inc in self.incidents.all_incidents()[:5]:
            items.append(
                pystray.MenuItem(
                    lambda item, i=inc: f"{i.incident_id} [{i.severity}] {i.title}"[:60],
                    lambda icon, item, i=inc: self._open_incident(i.incident_id),
                )
            )
        items += [
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open incident centre", self._open_centre),
            pystray.MenuItem("Check sensor health", self._open_health),
        ]
        return pystray.Menu(*items)

    def _open_incident(self, inc_id: str) -> None:
        webbrowser.open(f"{self.dashboard_url}/incident/{inc_id}")

    def _open_centre(self, icon=None, item=None) -> None:
        webbrowser.open(self.dashboard_url)

    def _open_health(self, icon=None, item=None) -> None:
        webbrowser.open(f"{self.dashboard_url}/health")

    # ------------------------------------------------------------------ #

    def snapshot(self) -> Dict[str, Any]:
        """Badge data for external consumers (kept separate from evidence)."""
        return {
            "unread_incidents": self.incidents.unread_count(),
            "active_incidents": self.incidents.active_count(),
            "active_sessions": len(getattr(self.incidents.session_tracker, "sessions", {}) or {}),
        }
