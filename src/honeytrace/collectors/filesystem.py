"""Filesystem event collector (Linux inotify via ctypes, no extra deps).

Important limitation (by design, documented): inotify reports filesystem
activity but carries NO actor information. Every filesystem event here is
marked with an unknown actor and low attribution confidence; reliable
attribution comes from the audit collector correlating the same path in the
same time window. This module therefore never guesses a PID.

Handles: recursive watch registration, new subdirectories, watch
invalidation recovery, queue overflow (IN_Q_OVERFLOW) and paths with
spaces or unusual Unicode (surrogateescape decoding).
"""

from __future__ import annotations

import ctypes
import os
import select
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from honeytrace.collectors import CollectorBase, STATUS_DEGRADED, STATUS_DISABLED, STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE

# inotify constants (linux/inotify.h)
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000

WATCH_MASK = (
    IN_OPEN | IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE
    | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF
)

EVENT_STRUCT = struct.Struct("iIII")  # wd, mask, cookie, len

EVENT_TYPE_MAP = {
    IN_OPEN: "file.open",
    IN_ACCESS: "file.access",
    IN_MODIFY: "file.modify",
    IN_ATTRIB: "file.attrib",
    IN_CLOSE_WRITE: "file.close_write",
    IN_CLOSE_NOWRITE: "file.close",
    IN_CREATE: "file.create",
    IN_DELETE: "file.delete",
}


class InotifyWatcher:
    """Thin ctypes wrapper over Linux inotify (import-safe everywhere)."""

    def __init__(self) -> None:
        self.fd = -1
        self.watch_descriptors: Dict[int, str] = {}

    @property
    def available(self) -> bool:
        return os.name == "posix"

    def open(self) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        self._libc = libc
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_add_watch.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_rm_watch.restype = ctypes.c_int
        libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        self.fd = libc.inotify_init1(os.O_NONBLOCK if hasattr(os, "O_NONBLOCK") else 0)
        if self.fd < 0:
            raise OSError("inotify_init1 failed")

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
            self.watch_descriptors.clear()

    def add_watch(self, path: str) -> Optional[int]:
        wd = self._libc.inotify_add_watch(self.fd, os.fsencode(path), WATCH_MASK)
        if wd < 0:
            return None
        self.watch_descriptors[wd] = path
        return wd

    def rm_watch(self, wd: int) -> None:
        self._libc.inotify_rm_watch(self.fd, wd)
        self.watch_descriptors.pop(wd, None)

    def read_events(self, timeout: float = 0.5) -> List[Dict[str, Any]]:
        """Blocking read with timeout. Returns parsed inotify events."""
        if self.fd < 0:
            return []
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return []
        try:
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        events: List[Dict[str, Any]] = []
        pos = 0
        while pos + EVENT_STRUCT.size <= len(data):
            wd, mask, cookie, name_len = EVENT_STRUCT.unpack_from(data, pos)
            pos += EVENT_STRUCT.size
            name_raw = data[pos : pos + name_len]
            pos += name_len
            name = name_raw.split(b"\x00", 1)[0].decode("utf-8", "surrogateescape") if name_len else ""
            events.append({"wd": wd, "mask": mask, "cookie": cookie, "name": name})
        return events


class FilesystemCollector(CollectorBase):
    name = "filesystem"

    def __init__(self, emit, settings, decoy_paths: Optional[Set[str]] = None):
        super().__init__(emit, settings)
        self.settings = settings
        self.decoy_paths = {str(p) for p in (decoy_paths or set())}
        self.watcher = InotifyWatcher()
        self.watch_roots: List[str] = []
        self.overflow_count = 0
        self.watch_losses = 0
        self.watched_dirs = 0
        if not self.watcher.available:
            self.status = STATUS_UNAVAILABLE
            self.status_detail = "inotify requires Linux"
        elif not settings.honeytrace.paths.monitored:
            self.status = STATUS_DISABLED
            self.status_detail = "no monitored paths configured"
        else:
            self.status = STATUS_OK

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        if self.status in (STATUS_UNAVAILABLE, STATUS_DISABLED):
            return
        try:
            self.watcher.open()
        except OSError as exc:
            self.status = STATUS_ERROR
            self.status_detail = str(exc)
            self.emit_gap(f"inotify init failed: {exc}")
            return

        for path in self.settings.monitored_paths():
            self._watch_recursive(str(path))
        self.watched_dirs = len(self.watcher.watch_descriptors)
        self.status = STATUS_OK if self.watched_dirs else STATUS_DEGRADED
        if not self.watched_dirs:
            self.status_detail = "no watches could be established"

        while not self.stopping:
            for ev in self.watcher.read_events(timeout=0.5):
                self._handle(ev)
        self.watcher.close()

    # ------------------------------------------------------------------ #

    def _watch_recursive(self, root: str) -> None:
        if not os.path.isdir(root):
            self.emit_gap(f"monitored path missing: {root}")
            return
        for dirpath, dirnames, _ in os.walk(root):
            if self.stopping:
                return
            if self.watcher.add_watch(dirpath) is None:
                self.watch_losses += 1
                self.emit_gap(f"failed to watch {dirpath}")

    def _handle(self, ev: Dict[str, Any]) -> None:
        mask = ev["mask"]
        if mask & IN_Q_OVERFLOW:
            self.overflow_count += 1
            self.status = STATUS_DEGRADED
            self.status_detail = "kernel event queue overflowed - events were lost"
            self.emit_gap("inotify queue overflow; events lost (coverage gap)")
            return

        base = self.watcher.watch_descriptors.get(ev["wd"])
        if base is None:
            return

        if mask & (IN_IGNORED | IN_UNMOUNT):
            self.watch_losses += 1
            self.watcher.watch_descriptors.pop(ev["wd"], None)
            if os.path.isdir(base):
                self.watcher.add_watch(base)
                self.emit_gap(f"watch invalidated and re-established for {base}")
            else:
                self.emit_gap(f"watch lost (path removed): {base}")
            return
        if mask & (IN_DELETE_SELF | IN_MOVE_SELF):
            return  # the IN_IGNORED that follows is handled above

        full_path = os.path.join(base, ev["name"]) if ev["name"] else base

        if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
            self.watcher.add_watch(full_path)

        event_type = self._classify(mask)
        if event_type is None:
            return
        if event_type == "file.rename" and not (mask & (IN_MOVED_FROM | IN_MOVED_TO)):
            return

        now = None
        self.emit(self._build_event(event_type, full_path, mask, ev["cookie"]))

    def _classify(self, mask: int) -> Optional[str]:
        for flag, event_type in EVENT_TYPE_MAP.items():
            if mask & flag:
                return event_type
        if mask & (IN_MOVED_FROM | IN_MOVED_TO):
            return "file.rename"
        return None

    def _build_event(self, event_type: str, path: str, mask: int, cookie: int) -> Dict[str, Any]:
        decoy = self.inventory_lookup(path)
        target: Dict[str, Any] = {"path": path, "kind": "dir" if mask & IN_ISDIR else "file"}
        if decoy:
            target["is_decoy"] = True
            target["decoy_id"] = decoy["decoy_id"]
        try:
            st = os.stat(path)
            target["size"] = st.st_size
            target["exists"] = True
        except OSError:
            target["exists"] = False

        return {
            "event_type": event_type,
            "source": self.name,
            "timestamp": None,  # observed now; inotify has no per-event clock
            "target": target,
            "actor": None,  # never guessed; audit correlation provides actors
            "process": None,
            "decoy_id": decoy["decoy_id"] if decoy else None,
            "details": {
                "mask": mask,
                "cookie": cookie or None,
                "inferred": False,
                "watched_root": self._root_of(path),
            },
            "observation": "observed",
            "confidence": 0.3 if decoy else 0.2,
        }

    def _root_of(self, path: str) -> str:
        for root in self.watch_roots or [str(p) for p in self.settings.monitored_paths()]:
            if path.startswith(root):
                return root
        return ""

    def inventory_lookup(self, path: str) -> Optional[Dict[str, Any]]:
        """Set by the daemon: resolves decoy_id for a path."""
        return self._inventory.by_path(path) if getattr(self, "_inventory", None) else None

    def attach_inventory(self, inventory) -> None:
        self._inventory = inventory

    # ------------------------------------------------------------------ #

    def health(self) -> Dict[str, Any]:
        h = super().health()
        h.update(
            {
                "watched_dirs": len(self.watcher.watch_descriptors),
                "overflow_count": self.overflow_count,
                "watch_losses": self.watch_losses,
            }
        )
        return h


# Backwards-compatible name used by tests importing the watcher directly.
FilesystemEvent = Dict[str, Any]
