"""Evidence verification: hash chain, sequence gaps and checkpoints.

Verification answers three questions:

1. Is every record's stored hash consistent with its content and its
   predecessor? (tamper detection within the chain)
2. Is the sequence contiguous, or are records missing? (gap detection,
   including torn/corrupt lines which read_events skips)
3. Does the chain anchor to a separately-protected checkpoint? (long-range
   rewrite detection - see README threat model for the honest limits of this)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.evidence.journal import journal_segments, read_events
from honeytrace.models.events import canonical_json


def _checkpoint_dirs(events_dir: Path) -> List[Path]:
    return [Path(events_dir) / "checkpoints"]


def _load_checkpoints(events_dir: Path) -> Dict[int, Dict[str, Any]]:
    """seq -> checkpoint body, keyed by chain position."""
    out: Dict[int, Dict[str, Any]] = {}
    for cp_dir in _checkpoint_dirs(events_dir):
        if not cp_dir.is_dir():
            continue
        for cp in sorted(cp_dir.glob("checkpoint-*.json")):
            try:
                body = json.loads(cp.read_text(encoding="utf-8"))
                out[int(body["seq"])] = body
            except (json.JSONDecodeError, KeyError, OSError, ValueError):
                continue
    return out


def verify_journal(
    events_dir: Path,
    key_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Walk the whole journal and verify chain + sequence + checkpoints."""
    report: Dict[str, Any] = {
        "ok": True,
        "records": 0,
        "verified": 0,
        "first_seq": None,
        "last_seq": None,
        "chain_head": None,
        "breaks": [],
        "gaps": [],
        "corrupt_lines": 0,
        "checkpoints_checked": 0,
        "checkpoint_failures": [],
        "notes": [],
    }

    prev_hash = "0" * 64
    prev_seq = 0
    checkpoints = _load_checkpoints(events_dir)
    key = None
    if key_path is not None and Path(key_path).exists():
        try:
            key = Path(key_path).read_bytes().strip()
        except OSError:
            key = None

    for seg in journal_segments(events_dir):
        try:
            fh = seg.open("r", encoding="utf-8")
        except OSError:
            report["notes"].append(f"segment unreadable: {seg.name}")
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    report["corrupt_lines"] += 1
                    report["ok"] = False
                    continue

                report["records"] += 1
                seq = rec.get("seq")
                rec_hash = rec.get("hash")
                body = {
                    "seq": seq,
                    "prev_hash": rec.get("prev_hash"),
                    "recorded_at_utc": rec.get("recorded_at_utc"),
                    "event": rec.get("event"),
                }
                expect = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()

                ok_hash = (expect == rec_hash) and (rec.get("prev_hash") == prev_hash)
                ok_seq = isinstance(seq, int) and seq == prev_seq + 1
                if ok_hash:
                    report["verified"] += 1
                else:
                    report["ok"] = False
                    report["breaks"].append(
                        {
                            "seq": seq,
                            "reason": "hash mismatch" if expect != rec_hash else "previous-hash mismatch",
                        }
                    )
                if not ok_seq and isinstance(seq, int):
                    report["ok"] = False
                    report["gaps"].append({"expected": prev_seq + 1, "found": seq})

                # Checkpoint anchoring.
                if isinstance(seq, int) and seq in checkpoints:
                    cp = checkpoints[seq]
                    report["checkpoints_checked"] += 1
                    cp_body = {
                        "seq": cp.get("seq"),
                        "last_hash": cp.get("last_hash"),
                        "chain_length": cp.get("chain_length"),
                        "written_at_utc": cp.get("written_at_utc"),
                    }
                    if cp.get("last_hash") != rec_hash:
                        report["ok"] = False
                        report["checkpoint_failures"].append(
                            {"seq": seq, "reason": "checkpoint does not anchor current chain"}
                        )
                    if key is not None:
                        mac = hmac.new(
                            key, canonical_json(cp_body).encode("utf-8"), hashlib.sha256
                        ).hexdigest()
                        if not hmac.compare_digest(mac, cp.get("hmac", "")):
                            report["ok"] = False
                            report["checkpoint_failures"].append(
                                {"seq": seq, "reason": "checkpoint HMAC invalid"}
                            )

                if isinstance(seq, int):
                    prev_seq = seq
                    prev_hash = rec_hash or prev_hash
                    if report["first_seq"] is None:
                        report["first_seq"] = seq
                    report["last_seq"] = seq
                    report["chain_head"] = rec_hash

    if report["records"] == 0:
        report["notes"].append("journal is empty or unreadable")
    if report["corrupt_lines"]:
        report["notes"].append(
            f"{report['corrupt_lines']} corrupt line(s) skipped - treat as evidence gaps"
        )
    return report


def verify_event_ids_unique(events_dir: Path) -> Dict[str, Any]:
    """Duplicate event IDs indicate a replayed or copied record."""
    seen: Dict[str, int] = {}
    dupes: List[str] = []
    for rec in read_events(events_dir):
        eid = rec.get("event", {}).get("event_id")
        if not eid:
            continue
        seen[eid] = seen.get(eid, 0) + 1
        if seen[eid] == 2:
            dupes.append(eid)
    return {"duplicates": dupes, "count": len(dupes)}


def coverage_summary(events_dir: Path) -> Dict[str, Any]:
    """Dropped-event / collector-gap summary for the whole journal."""
    dropped = gaps = 0
    sources: Dict[str, int] = {}
    last_by_source: Dict[str, str] = {}
    for rec in read_events(events_dir):
        ev = rec.get("event", {})
        src = ev.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1
        last_by_source[src] = ev.get("timestamp_utc", "")
        if ev.get("event_type") == "health.gap":
            gaps += 1
    return {"events_per_source": sources, "gap_events": gaps, "last_event_by_source": last_by_source}
