"""Artifact manifest: an append-only index of collected artifacts.

Each entry records path, type, size, sha256, timestamps, the collection
source and related event IDs. Hashes are verified before export.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.evidence.hashing import sha256_file
from honeytrace.models.events import new_event_id


def _utc() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class ArtifactManifest:
    """Append-only JSONL manifest stored under data/manifests/."""

    def __init__(self, manifest_dir: Path):
        self.dir = Path(manifest_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.active = self.dir / "manifest.jsonl"

    def add(
        self,
        path: Path,
        artifact_type: str,
        source: str,
        related_event_ids: Optional[List[str]] = None,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Index one artifact. The file must exist; hash it now."""
        path = Path(path)
        if not path.is_file():
            return None
        stat = path.stat()
        entry = {
            "artifact_id": new_event_id(),
            "path": str(path),
            "type": artifact_type,
            "size": stat.st_size,
            "sha256": sha256_file(path),
            "mtime_utc": _utc(),
            "collected_at_utc": _utc(),
            "source": source,
            "related_event_ids": related_event_ids or [],
            "notes": notes,
        }
        with self.active.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        return entry

    def entries(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not self.active.exists():
            return out
        with self.active.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def find_by_event(self, event_id: str) -> List[Dict[str, Any]]:
        return [e for e in self.entries() if event_id in (e.get("related_event_ids") or [])]

    def verify_all(self) -> Dict[str, Any]:
        """Re-hash every artifact. Returns a verification report."""
        total = missing = mismatched = 0
        problems: List[Dict[str, str]] = []
        for entry in self.entries():
            total += 1
            p = Path(entry["path"])
            if not p.is_file():
                missing += 1
                problems.append({"artifact_id": entry["artifact_id"], "path": entry["path"], "issue": "missing"})
                continue
            actual = sha256_file(p)
            if actual != entry.get("sha256"):
                mismatched += 1
                problems.append({"artifact_id": entry["artifact_id"], "path": entry["path"], "issue": "hash mismatch"})
        return {
            "total": total,
            "verified": total - missing - mismatched,
            "missing": missing,
            "mismatched": mismatched,
            "problems": problems,
            "verified_at_utc": _utc(),
        }

    def prune_missing(self) -> int:
        """Remove manifest entries whose artifacts vanished (e.g. pcap ring
        rotation). The manifest is ours; artifacts belong to the operator."""
        before = len(self.entries())
        keep = [e for e in self.entries() if Path(e["path"]).is_file()]
        removed = before - len(keep)
        if removed:
            tmp = self.active.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                for e in keep:
                    fh.write(json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
            os.replace(tmp, self.active)
        return removed
