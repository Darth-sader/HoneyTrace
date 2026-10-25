"""Optional PCAP ring-buffer collector (tcpdump subprocess).

Opt-in (network.pcap_enabled), bounded, and header-focused by default:
    tcpdump -i <iface> -s <snaplen> -w <ring> -G <rotate_seconds> -W <count> -U

HoneyTrace records capture start/end, hashes each rotated file into the
artifact manifest, and parses tcpdump's stderr for packet-drop statistics.
PCAP can contain sensitive traffic - keep it pointed at the lab interface
and leave snaplen small unless the experiment explicitly needs payloads.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.collectors import STATUS_DISABLED, STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE, CollectorBase

DROP_RE = re.compile(r"(\d+) packets dropped by kernel", re.I)
DROP_RE_ALT = re.compile(r"packets dropped by kernel:\s*(\d+)", re.I)


class PcapCollector(CollectorBase):
    name = "pcap"

    def __init__(self, emit, settings, manifest=None):
        super().__init__(emit, settings)
        self.settings = settings
        cfg = settings.honeytrace.network
        self.manifest = manifest
        self.iface = cfg.pcap_interface
        self.snaplen = cfg.pcap_snaplen
        self.rotate_seconds = cfg.pcap_rotate_seconds
        self.ring_count = min(cfg.pcap_ring_count, settings.retention.pcap.max_files)
        self.pcap_dir = settings.data_dir / "pcap"
        self.proc: Optional[subprocess.Popen] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self.drop_stats = 0
        self.captured_files: List[str] = []
        self.started_utc: Optional[str] = None
        self.ended_utc: Optional[str] = None

        if not cfg.pcap_enabled:
            self.status = STATUS_DISABLED
            self.status_detail = "pcap disabled in configuration"
        elif os.name != "posix" or not shutil.which("tcpdump"):
            self.status = STATUS_UNAVAILABLE
            self.status_detail = "tcpdump not found"
        elif not self._can_capture():
            self.status = STATUS_UNAVAILABLE
            self.status_detail = "insufficient privileges for packet capture (need root or CAP_NET_ADMIN)"
        else:
            self.status = STATUS_OK

    def _can_capture(self) -> bool:
        try:
            probe = subprocess.run(
                ["tcpdump", "-D"], capture_output=True, text=True, timeout=5
            )
            return probe.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        if self.status != STATUS_OK:
            self.emit_gap(f"pcap sensor unavailable: {self.status_detail}")
            return
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        ring = self.pcap_dir / "honeytrace.pcap"
        cmd = [
            "tcpdump", "-i", self.iface, "-s", str(self.snaplen),
            "-w", str(ring), "-G", str(self.rotate_seconds),
            "-W", str(self.ring_count), "-U",
        ]
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
        except OSError as exc:
            self.status = STATUS_ERROR
            self.status_detail = str(exc)
            self.emit_gap(f"tcpdump failed to start: {exc}")
            return

        from honeytrace.models.events import utc_now_iso

        self.started_utc = utc_now_iso()
        self._stderr_thread = threading.Thread(target=self._consume_stderr, daemon=True)
        self._stderr_thread.start()

        while not self.stopping:
            if self.proc.poll() is not None:
                self.status = STATUS_ERROR
                self.status_detail = "tcpdump exited unexpectedly"
                self.emit_gap("tcpdump exited unexpectedly (coverage gap)")
                break
            self._manifest_new_files()
            self.sleep(max(2, self.rotate_seconds))

        self._stop_capture()

    def _consume_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for raw in iter(self.proc.stderr.readline, b""):
            line = raw.decode("utf-8", "replace")
            m = DROP_RE.search(line) or DROP_RE_ALT.search(line)
            if m:
                try:
                    self.drop_stats = max(self.drop_stats, int(m.group(1)))
                except ValueError:
                    pass

    def _manifest_new_files(self) -> None:
        if self.manifest is None:
            return
        for p in sorted(self.pcap_dir.glob("honeytrace*.pcap*")):
            sp = str(p)
            if sp in self.captured_files:
                continue
            if p.stat().st_size == 0:
                continue
            entry = self.manifest.add(
                p, "pcap", self.name,
                related_event_ids=[],
                notes=f"ring interface={self.iface} snaplen={self.snaplen}",
            )
            if entry:
                self.captured_files.append(sp)
                self.emit(
                    {
                        "event_type": "pcap.rotation",
                        "target": {"path": sp},
                        "details": {
                            "artifact_id": entry["artifact_id"],
                            "size": entry["size"],
                            "sha256": entry["sha256"],
                            "interface": self.iface,
                        },
                        "observation": "observed",
                        "confidence": 1.0,
                    }
                )

    def _stop_capture(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        from honeytrace.models.events import utc_now_iso

        self.ended_utc = utc_now_iso()
        self._manifest_new_files()
        self.emit(
            {
                "event_type": "pcap.session_end",
                "details": {
                    "started_utc": self.started_utc,
                    "ended_utc": self.ended_utc,
                    "interface": self.iface,
                    "files": len(self.captured_files),
                    "kernel_drops": self.drop_stats,
                },
                "observation": "observed",
                "confidence": 1.0,
            }
        )

    def health(self) -> Dict[str, Any]:
        h = super().health()
        h.update(
            {
                "interface": self.iface,
                "ring_files": len(self.captured_files),
                "kernel_drops": self.drop_stats,
                "started_utc": self.started_utc,
            }
        )
        return h
