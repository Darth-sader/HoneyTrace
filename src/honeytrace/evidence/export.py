"""Evidence export: package a case bundle for offline analysis.

An export contains:
    events.jsonl               (journal copy, verified before inclusion)
    verification.json          (chain/manifest verification report)
    manifest.jsonl             (artifact manifest)
    incidents/<id>.json        (requested incidents)
    artifacts/                 (approved artifacts, hash-verified)
    REPORT.txt                 (what this bundle does and does not prove)

The bundle deliberately includes the limitations text so the exported case
cannot be mistaken for complete proof.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.evidence.hashing import sha256_file
from honeytrace.evidence.journal import iter_raw_events, read_events
from honeytrace.evidence.verification import verify_journal
from honeytrace.models.events import canonical_json

LIMITATIONS_TEXT = """HoneyTrace evidence export
===========================

This bundle was produced by HoneyTrace, a lab deception/detection tool.

What this bundle is:
  - a verifiable copy of HoneyTrace's collected events, incidents,
    manifests and approved artifacts at export time.

What this bundle is NOT:
  - proof of who performed any action. IP addresses, usernames and process
    IDs are technical observations, not identities.
  - complete. Sensors have blind spots; dropped events and coverage gaps
    are recorded in the journal and in verification.json.
  - tamper-proof against an attacker with root. The hash chain and the
    separately-protected checkpoints make silent modification detectable
    on the happy path, but a root-level attacker can rewrite local files
    including checkpoints. Treat chain verification as one signal among
    several.

Verify with:  honeytrace verify --bundle <this-file>.zip
"""


def _utc() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class CaseExporter:
    def __init__(self, settings, manifest, incidents_dir: Path):
        self.settings = settings
        self.manifest = manifest
        self.incidents_dir = Path(incidents_dir)

    def export(
        self,
        out_path: Path,
        incident_ids: Optional[List[str]] = None,
        include_artifacts: bool = True,
    ) -> Dict[str, Any]:
        events_dir = self.settings.data_dir / "events"
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Verify BEFORE packaging; never export an unverified chain silently.
        key_path = self.settings.data_dir / "state" / "checkpoint.key"
        chain_report = verify_journal(events_dir, key_path=key_path)
        manifest_report = self.manifest.verify_all()

        selected_events: List[Dict[str, Any]] = []
        wanted = set(incident_ids or [])

        # Events are journaled BEFORE incidents exist, so incident membership
        # is resolved through the incident's own event-id references as well.
        referenced_ids: set = set()
        selected_incidents: List[Dict[str, Any]] = []
        if self.incidents_dir.is_dir():
            for inc_file in sorted(self.incidents_dir.glob("incident-*.json")):
                try:
                    body = json.loads(inc_file.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                if not wanted or body.get("incident_id") in wanted:
                    selected_incidents.append(body)
                    referenced_ids.update(body.get("event_ids") or [])

        for ev in iter_raw_events(events_dir):
            if not wanted or ev.get("incident_id") in wanted or ev.get("event_id") in referenced_ids:
                selected_events.append(ev)

        artifacts_included: List[Dict[str, str]] = []
        if include_artifacts:
            approved = tuple(self.settings.retention.export.approved_artifact_suffixes)
            for entry in self.manifest.entries():
                p = Path(entry["path"])
                if not p.is_file():
                    continue
                if approved and not p.suffix.lower() in approved:
                    continue
                if sha256_file(p) != entry.get("sha256"):
                    continue  # unverified artifact never travels
                artifacts_included.append(
                    {"path": entry["path"], "sha256": entry["sha256"], "artifact_id": entry["artifact_id"]}
                )

        index = {
            "exported_at_utc": _utc(),
            # A filtered export contains a SUBSET of the chain: continuity
            # across records cannot hold there, so per-record content
            # integrity is what verification guarantees for such bundles.
            "complete_chain": not bool(wanted),
            "chain_report": {k: v for k, v in chain_report.items() if k != "notes"} | {"notes": chain_report["notes"]},
            "manifest_report": manifest_report,
            "event_count": len(selected_events),
            "incident_count": len(selected_incidents),
            "artifacts": artifacts_included,
        }

        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("REPORT.txt", LIMITATIONS_TEXT)
            zf.writestr("index.json", canonical_json(index))
            # Journal as raw records (chain preserved) for the event lines.
            events_lines = []
            for rec in read_events(events_dir):
                ev = rec.get("event", {})
                if not wanted or ev.get("incident_id") in wanted or ev.get("event_id") in referenced_ids:
                    events_lines.append(canonical_json(rec))
            zf.writestr("events.jsonl", "\n".join(events_lines))
            zf.writestr("manifest.jsonl", self._manifest_text())
            for inc in selected_incidents:
                zf.writestr(
                    f"incidents/{inc.get('incident_id', 'unknown')}.json",
                    canonical_json(inc),
                )
            for art in artifacts_included:
                src = Path(art["path"])
                arcname = "artifacts/" + src.name
                try:
                    zf.write(src, arcname)
                except OSError:
                    continue

        return index

    def _manifest_text(self) -> str:
        lines = []
        for e in self.manifest.entries():
            lines.append(canonical_json(e))
        return "\n".join(lines)


def verify_bundle(bundle_path: Path) -> Dict[str, Any]:
    """Verify an exported bundle on any machine.

    Guarantees by bundle type:
    * complete export (index.complete_chain)  - full hash-chain continuity
    * filtered export (per-incident)          - per-record content integrity
      plus strictly increasing sequence numbers (cross-record continuity is
      expected to be broken by the filter and is NOT treated as tampering)
    """
    report: Dict[str, Any] = {"ok": True, "issues": [], "events": 0, "artifacts": 0}
    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = set(zf.namelist())
        complete_chain = True
        idx: Dict[str, Any] = {}
        if "index.json" in names:
            idx = json.loads(zf.read("index.json").decode("utf-8"))
            complete_chain = bool(idx.get("complete_chain", True))
        prev_hash = "0" * 64
        prev_seq = 0
        for line in zf.read("events.jsonl").decode("utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            report["events"] += 1
            body = {
                "seq": rec.get("seq"),
                "prev_hash": rec.get("prev_hash"),
                "recorded_at_utc": rec.get("recorded_at_utc"),
                "event": rec.get("event"),
            }
            expect = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if expect != rec.get("hash"):
                report["ok"] = False
                report["issues"].append(f"record hash mismatch at seq {rec.get('seq')}")
            if complete_chain and rec.get("prev_hash") != prev_hash:
                report["ok"] = False
                report["issues"].append(f"chain break at seq {rec.get('seq')}")
            if not complete_chain and isinstance(rec.get("seq"), int) and rec["seq"] <= prev_seq:
                report["ok"] = False
                report["issues"].append(f"sequence not increasing at seq {rec.get('seq')}")
            prev_hash = rec.get("hash", prev_hash)
            if isinstance(rec.get("seq"), int):
                prev_seq = rec["seq"]
        if "index.json" in names:
            for art in idx.get("artifacts", []):
                arcname = "artifacts/" + Path(art["path"]).name
                report["artifacts"] += 1
                if arcname not in names:
                    report["ok"] = False
                    report["issues"].append(f"artifact missing from bundle: {arcname}")
                    continue
                if _sha256_bytes(zf.read(arcname)) != art["sha256"]:
                    report["ok"] = False
                    report["issues"].append(f"artifact hash mismatch: {arcname}")
    return report


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
