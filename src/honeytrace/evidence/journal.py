"""Append-only JSONL evidence journal with hash chaining.

Design contract
---------------
* One normalized JSON object per line in ``data/events/events.jsonl``.
* The writer owns an internal queue: collector threads never block on disk.
  When the queue is full the event is DROPPED and counted - never silently.
* Every record is chained: ``hash = sha256(canonical({seq, prev_hash,
  recorded_at_utc, event}))``. A re-writing attacker must recompute the
  whole chain; separately protected HMAC checkpoints anchor it periodically
  (see the threat-model notes in README.md - this is tamper *evidence*,
  not tamper *prevention*).
* Ingestion is the only writer. Reports read; they never edit.

Record shape::

    {"seq": 12, "prev_hash": "...", "recorded_at_utc": "...",
     "event": {...}, "hash": "..."}

The checkpoint key lives OUTSIDE the evidence directory by default
(``data/state/checkpoint.key``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from honeytrace.models.events import canonical_json

SENTINEL = object()


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"


class JournalWriter:
    """Queue-fed, hash-chained JSONL writer."""

    def __init__(
        self,
        events_dir: Path,
        key_path: Path,
        max_segment_bytes: int = 50 * 1024 * 1024,
        max_segments: int = 20,
        checkpoint_every: int = 500,
        queue_size: int = 20000,
        fsync_interval: float = 1.0,
    ):
        self.events_dir = Path(events_dir)
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_dir = self.events_dir / "checkpoints"
        self.checkpoint_dir.mkdir(exist_ok=True)

        self.key_path = Path(key_path)
        self._key = self._load_or_create_key()

        self.max_segment_bytes = max_segment_bytes
        self.max_segments = max_segments
        self.checkpoint_every = checkpoint_every
        self.fsync_interval = fsync_interval

        self._queue: "queue.Queue[Any]" = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # RLock: _fsync/_write_checkpoint run both standalone and from inside
        # other locked sections (rotate/close) - a plain Lock would deadlock.
        self._lock = threading.RLock()
        self._seq = 0
        self._prev_hash = "0" * 64
        self._fh = None
        self._active_path = self.events_dir / "events.jsonl"
        self._segment_no = self._detect_last_segment()
        self._bytes_written_active = 0
        # Resume the chain from whatever is already on disk so a daemon
        # restart continues the SAME hash chain instead of forking it.
        self._resume_chain()

        # Health/coverage counters (read by honeytrace.health).
        self.dropped_events = 0
        self.storage_errors = 0
        self.last_event_utc: Optional[str] = None
        self.total_written = 0
        self.storage_alert: Optional[str] = None

    # -- public API --------------------------------------------------------- #

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="honeytrace-journal", daemon=True)
        self._thread.start()

    def append(self, event: Dict[str, Any]) -> bool:
        """Enqueue an event. Returns False when the queue is full (dropped)."""
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            with self._lock:
                self.dropped_events += 1
                self.storage_alert = "journal queue full - events being dropped"
            return False

    def queue_depth(self) -> int:
        return self._queue.qsize()

    def flush(self, timeout: float = 10.0) -> bool:
        """Drain the queue and fsync. Used at shutdown and before exports."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._queue.empty():
                self._fsync()
                return True
            time.sleep(0.02)
        return self._queue.empty()

    def close(self, timeout: float = 10.0) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(SENTINEL)
        except queue.Full:
            # Drain one and retry; evidence integrity beats completeness here.
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(SENTINEL)
            except queue.Full:  # pragma: no cover
                pass
        if self._thread:
            self._thread.join(timeout=timeout)
        with self._lock:
            self._write_checkpoint_locked()
            self._fsync()
            if self._fh:
                self._fh.close()
                self._fh = None

    # -- writer thread ------------------------------------------------------ #

    def _run(self) -> None:
        last_fsync = time.monotonic()
        while True:
            try:
                item = self._queue.get(timeout=0.25)
            except queue.Empty:
                if time.monotonic() - last_fsync >= self.fsync_interval:
                    self._fsync()
                    last_fsync = time.monotonic()
                if self._stop.is_set():
                    break
                continue

            if item is SENTINEL:
                break
            try:
                self._write_event(item)
            except OSError as exc:
                # Disk full / IO error: record the gap, keep the daemon alive.
                with self._lock:
                    self.storage_errors += 1
                    self.dropped_events += 1
                    self.storage_alert = f"evidence write failed: {exc}"
                continue
            except Exception:  # malformed event must not kill the journal
                with self._lock:
                    self.storage_errors += 1
                continue
            if time.monotonic() - last_fsync >= self.fsync_interval:
                self._fsync()
                last_fsync = time.monotonic()

    def _write_event(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._rotate_if_needed_locked()
            self._seq += 1
            event = dict(event)
            event["sequence"] = self._seq
            recorded_at = _utc()
            body = {
                "seq": self._seq,
                "prev_hash": self._prev_hash,
                "recorded_at_utc": recorded_at,
                "event": event,
            }
            rec_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            line = canonical_json({**body, "hash": rec_hash})
            fh = self._ensure_file_locked()
            fh.write(line + "\n")
            self._bytes_written_active += len(line) + 1
            self._prev_hash = rec_hash
            self.total_written += 1
            self.last_event_utc = recorded_at
            if self.checkpoint_every and self._seq % self.checkpoint_every == 0:
                self._write_checkpoint_locked()

    # -- internals ---------------------------------------------------------- #

    def _detect_last_segment(self) -> int:
        highest = 0
        for p in self.events_dir.glob("events.*.jsonl"):
            try:
                no = int(p.name.split(".")[1])
                highest = max(highest, no)
            except (IndexError, ValueError):
                continue
        return highest

    def _resume_chain(self) -> None:
        """Seed (seq, prev_hash) from the last valid record on disk."""
        for seg in reversed(journal_segments(self.events_dir)):
            try:
                last_valid: Optional[Dict[str, Any]] = None
                with seg.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue  # torn write from a hard kill: skip
                        if isinstance(rec.get("seq"), int) and rec.get("hash"):
                            last_valid = rec
                if last_valid is not None:
                    self._seq = last_valid["seq"]
                    self._prev_hash = last_valid["hash"]
                    return
            except OSError:
                continue

    def _ensure_file_locked(self):
        if self._fh is None:
            self._fh = self._active_path.open("a", encoding="utf-8")
            try:
                self._bytes_written_active = self._active_path.stat().st_size
            except OSError:
                self._bytes_written_active = 0
        return self._fh

    def _rotate_if_needed_locked(self) -> None:
        if self._fh is None or self._bytes_written_active < self.max_segment_bytes:
            return
        self._fsync()
        self._fh.close()
        self._fh = None
        self._segment_no += 1
        rotated = self.events_dir / f"events.{self._segment_no:06d}.jsonl"
        self._active_path.replace(rotated)
        self._prune_old_segments_locked()

    def _prune_old_segments_locked(self) -> None:
        segments = sorted(self.events_dir.glob("events.*.jsonl"))
        excess = len(segments) - self.max_segments
        for old in segments[:max(0, excess)]:
            try:
                old.unlink()
            except OSError:
                pass

    def _fsync(self) -> None:
        with self._lock:
            if self._fh:
                try:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                except OSError as exc:
                    self.storage_errors += 1
                    self.storage_alert = f"fsync failed: {exc}"

    def _write_checkpoint_locked(self) -> None:
        if self._seq == 0:
            return
        body = {
            "seq": self._seq,
            "last_hash": self._prev_hash,
            "chain_length": self._seq,
            "written_at_utc": _utc(),
        }
        mac = hmac.new(self._key, canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()
        cp_path = self.checkpoint_dir / f"checkpoint-{self._seq:012d}.json"
        tmp = cp_path.with_suffix(".tmp")
        tmp.write_text(canonical_json({**body, "hmac": mac}), encoding="utf-8")
        os.replace(tmp, cp_path)
        self._restrict_permissions(cp_path)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            data = self.key_path.read_bytes().strip()
            if data:
                return data
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_hex(32).encode()
        self.key_path.write_bytes(key + b"\n")
        self._restrict_permissions(self.key_path)
        return key

    @staticmethod
    def _restrict_permissions(path: Path) -> None:
        if os.name == "posix":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    # -- stats -------------------------------------------------------------- #

    def stats(self) -> Dict[str, Any]:
        return {
            "sequence": self._seq,
            "queue_depth": self.queue_depth(),
            "dropped_events": self.dropped_events,
            "storage_errors": self.storage_errors,
            "total_written": self.total_written,
            "last_event_utc": self.last_event_utc,
            "storage_alert": self.storage_alert,
            "active_file": str(self._active_path),
        }


def journal_segments(events_dir: Path) -> List[Path]:
    """All journal segment paths in chain order (rotated, then active)."""
    segments = sorted(
        Path(events_dir).glob("events.*.jsonl"),
        key=lambda p: int(p.name.split(".")[1]) if p.name.split(".")[1].isdigit() else 0,
    )
    active = Path(events_dir) / "events.jsonl"
    if active.exists():
        segments.append(active)
    return segments


def read_events(events_dir: Path, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """Stream parsed records from the journal, oldest first."""
    count = 0
    for seg in journal_segments(events_dir):
        try:
            with seg.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                        count += 1
                        if limit is not None and count >= limit:
                            return
                    except json.JSONDecodeError:
                        # A torn/corrupt line is a gap; verification reports it.
                        continue
        except OSError:
            continue


def iter_raw_events(events_dir: Path, limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """Stream just the event payloads (sequence/hash envelope stripped)."""
    count = 0
    for rec in read_events(events_dir):
        ev = rec.get("event")
        if isinstance(ev, dict):
            yield ev
            count += 1
            if limit is not None and count >= limit:
                return
