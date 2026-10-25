"""Decoy inventory: the authoritative record of HoneyTrace-owned decoys.

Every decoy gets a stable decoy_id, path, type, hash, ownership, creation
time, purpose and token reference. Cleanup removes ONLY files listed here
(and only when their hash still matches - a modified decoy is evidence and
is preserved, with a note).
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.evidence.hashing import sha256_file


def _utc() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class DecoyInventory:
    """JSON inventory at data/decoys/inventory.json."""

    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "decoys" / "inventory.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._decoys: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                body = json.loads(self.path.read_text(encoding="utf-8"))
                for d in body.get("decoys", []):
                    self._decoys[d["decoy_id"]] = d
            except (json.JSONDecodeError, KeyError, OSError):
                pass

    def _save(self) -> None:
        body = {"updated_at_utc": _utc(), "decoys": list(self._decoys.values())}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)

    def register(
        self,
        decoy_id: str,
        path: Path,
        decoy_type: str,
        profile: str,
        sha256: str,
        token_url: Optional[str] = None,
        purpose: str = "decoy",
    ) -> Dict[str, Any]:
        entry = {
            "decoy_id": decoy_id,
            "path": str(Path(path)),
            "type": decoy_type,
            "content_profile": profile,
            "sha256": sha256,
            "token_url": token_url,
            "purpose": purpose,
            "created_at_utc": _utc(),
            "owner_uid": None,
            "integrity": "ok",
        }
        with self._lock:
            self._decoys[decoy_id] = entry
            self._save()
        return entry

    def attach_process_info(self, decoy_id: str) -> None:
        """Record the owning UID when running on POSIX."""
        try:
            entry = self._decoys[decoy_id]
            entry["owner_uid"] = os.stat(entry["path"]).st_uid
            self._save()
        except (KeyError, OSError):
            pass

    def all(self) -> List[Dict[str, Any]]:
        return list(self._decoys.values())

    def get(self, decoy_id: str) -> Optional[Dict[str, Any]]:
        return self._decoys.get(decoy_id)

    def by_path(self, path: str) -> Optional[Dict[str, Any]]:
        for d in self._decoys.values():
            if d["path"] == str(path):
                return d
        return None

    def check_integrity(self) -> List[Dict[str, Any]]:
        """Re-hash every decoy; mark modified/missing ones."""
        changed: List[Dict[str, Any]] = []
        with self._lock:
            for d in self._decoys.values():
                p = Path(d["path"])
                if not p.exists():
                    state = "missing"
                else:
                    state = "ok" if sha256_file(p) == d["sha256"] else "modified"
                if state != d.get("integrity"):
                    d["integrity"] = state
                    changed.append(d)
            if changed:
                self._save()
        return changed

    def cleanup(self, force: bool = False) -> Dict[str, Any]:
        """Remove decoys HoneyTrace owns. Modified decoys are preserved
        unless force=True, because they are potential evidence."""
        report = {"removed": [], "preserved": [], "missing": 0}
        with self._lock:
            for decoy_id, d in list(self._decoys.items()):
                p = Path(d["path"])
                if not p.exists():
                    report["missing"] += 1
                    del self._decoys[decoy_id]
                    continue
                current = sha256_file(p)
                if current != d["sha256"] and not force:
                    report["preserved"].append({"decoy_id": decoy_id, "path": d["path"],
                                                "reason": "modified since creation - potential evidence"})
                    continue
                try:
                    p.unlink()
                    report["removed"].append(d["path"])
                    # Remove now-empty group dirs we created (only under the decoy).
                    parent = p.parent
                    while parent != parent.parent and not any(parent.iterdir()):
                        parent.rmdir()
                        parent = parent.parent
                except OSError:
                    report["preserved"].append({"decoy_id": decoy_id, "path": d["path"],
                                                "reason": "unlink failed"})
                    continue
                del self._decoys[decoy_id]
            self._save()
        return report
