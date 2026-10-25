"""Response policy engine and scoped, reversible containment.

Safety architecture (read before touching):

1. Detection and response are separate. Rules fire -> the incident manager
   records -> THIS engine evaluates policy. Collectors never block anything.
2. Gating, in order: response.enabled -> rule policy -> mode (observe
   records proposals only) -> arming switch (containment needs an explicit
   `honeytrace arm --mode contain --confirm`) -> dry-run -> trusted-owner
   bypass. Every gate decision is recorded, including refusals.
3. Containment is scoped to the dedicated lab user's UID only. Host-wide
   OUTPUT rules are never created. Every applied action stores its exact
   rollback command and previous state in a rollback journal
   (data/state/rollback.jsonl); rollback touches ONLY rules tagged
   `honeytrace:` - unrelated firewall configuration is never modified.
4. `emergency_off()` is idempotent and stops new actions before rolling back.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from honeytrace.models.events import canonical_json
from honeytrace.models.incidents import Incident, ResponseActionRecord, RuleMatch

ARMING_STATES = ("disarmed", "armed", "degraded", "stopping")


def _utc() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class ArmingState:
    """Operator arming switch, persisted OUTSIDE the evidence directory."""

    def __init__(self, state_dir: Path):
        self.path = Path(state_dir) / "arming.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.body: Dict[str, Any] = {
            "state": "disarmed",
            "mode": "observe",
            "containment_armed": False,
            "armed_at_utc": None,
            "armed_by": None,
            "updated_at_utc": None,
        }
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                self.body.update(json.loads(self.path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, OSError):
                pass

    def save(self) -> None:
        self.body["updated_at_utc"] = _utc()
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.body, indent=2), encoding="utf-8")
        tmp.replace(self.path)
        if os.name == "posix":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def arm(self, mode: str, by: str = "operator", confirm_containment: bool = False) -> None:
        self.body["state"] = "armed"
        self.body["mode"] = mode
        self.body["armed_at_utc"] = _utc()
        self.body["armed_by"] = by
        self.body["containment_armed"] = bool(mode == "contain" and confirm_containment)
        self.save()

    def disarm(self) -> None:
        self.body["state"] = "disarmed"
        self.body["containment_armed"] = False
        self.save()

    def set_state(self, state: str) -> None:
        if state in ARMING_STATES:
            self.body["state"] = state
            self.save()

    @property
    def mode(self) -> str:
        return self.body.get("mode", "observe")

    @property
    def containment_armed(self) -> bool:
        return bool(self.body.get("containment_armed"))


class FirewallManager:
    """Scoped firewall rules tagged for rollback. Lab-UID only."""

    TAG_PREFIX = "honeytrace"

    def __init__(self, backend: str = "iptables"):
        self.backend = backend if shutil.which(backend) else ("iptables" if shutil.which("iptables") else backend)
        self.last_error: Optional[str] = None

    def _run(self, args: List[str], timeout: float = 8.0) -> Tuple[bool, str]:
        try:
            proc = subprocess.run(
                [self.backend, *args], capture_output=True, text=True, timeout=timeout
            )
            return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.last_error = str(exc)
            return False, str(exc)

    def _rule_spec(self, uid: int, tag: str) -> List[str]:
        """One REJECT rule scoped to the lab UID, tagged for identification."""
        tag_flag = f"{self.TAG_PREFIX}:{tag}"
        if self.backend == "nft":
            return ["insert", "rule", "inet", "honeytrace", "output",
                    "meta", "skuid", str(uid), "counter", "reject",
                    "comment", tag_flag]
        return ["-I", "OUTPUT", "-m", "owner", "--uid-owner", str(uid),
                "-m", "comment", "--comment", tag_flag, "-j", "REJECT"]

    def list_rules(self) -> List[str]:
        if self.backend == "nft":
            ok, out = self._run(["list", "table", "inet", "honeytrace"])
            return out.splitlines() if ok else []
        ok, out = self._run(["-S", "OUTPUT"])
        return out.splitlines() if ok else []

    def has_rule(self, uid: int, tag: str) -> bool:
        marker = f"{self.TAG_PREFIX}:{tag}"
        return any(marker in line for line in self.list_rules())

    def apply_isolation(self, uid: int, tag: str) -> ResponseActionRecord:
        """Add the scoped REJECT rule. Idempotent."""
        record = ResponseActionRecord(
            action_id=uuid.uuid4().hex,
            action="isolate",
            status="failed",
            target=f"uid:{uid}",
            reason=f"scoped outbound restriction tagged {self.TAG_PREFIX}:{tag}",
        )
        if self.backend == "nft":
            # Create the dedicated table (idempotent) then the rule.
            self._run(["add", "table", "inet", "honeytrace"])
            self._run(["add", "chain", "inet", "honeytrace", "output",
                       "{", "type", "filter", "hook", "output", "priority", "-150",
                       ";", "policy", "accept;", "}"])
        previous = "\n".join(self.list_rules())
        if self.has_rule(uid, tag):
            record.status = "applied"
            record.reason += " (already present - idempotent no-op)"
            record.previous_state = previous
            return record
        ok, out = self._run(self._rule_spec(uid, tag))
        record.previous_state = previous
        record.rollback_cmd = (
            f"nft delete rule inet honeytrace handle <handle>"
            if self.backend == "nft"
            else f"{self.backend} -D OUTPUT -m owner --uid-owner {uid} -m comment --comment {self.TAG_PREFIX}:{tag} -j REJECT"
        )
        record.applied_at_utc = _utc()
        record.status = "applied" if ok else "failed"
        if not ok:
            record.rollback_result = out
        return record

    def remove_rule(self, uid: int, tag: str) -> Tuple[bool, str]:
        """Rollback: delete ONLY the tagged rule. Safe to run repeatedly."""
        marker = f"{self.TAG_PREFIX}:{tag}"
        if self.backend == "nft":
            # Echo handles, delete matching ones by handle.
            ok, out = self._run(["-a", "list", "table", "inet", "honeytrace"])
            results = []
            if ok:
                for line in out.splitlines():
                    if marker in line and "handle" in line:
                        handle = line.split("handle")[-1].strip().split()[0]
                        results.append(self._run(["delete", "rule", "inet", "honeytrace", "handle", handle]))
            return all(r[0] for r in results) if results else (True, "no matching rules")
        ok, out = self._run(["-D", "OUTPUT", "-m", "owner", "--uid-owner", str(uid),
                             "-m", "comment", "--comment", marker, "-j", "REJECT"])
        if ok:
            return True, "removed"
        return (True, "already absent") if "Bad rule" in out or "does it exist" in out else (ok, out)


class ResponseEngine:
    """Maps confirmed rule matches to log/alert/isolate/throttle actions."""

    def __init__(
        self,
        settings,
        arming: ArmingState,
        journal=None,
        rollback_path: Optional[Path] = None,
    ):
        self.settings = settings
        self.arming = arming
        self.journal = journal
        self.firewall = FirewallManager(settings.honeytrace.containment.firewall_backend)
        self.rollback_path = Path(rollback_path or (settings.data_dir / "state" / "rollback.jsonl"))
        self.rollback_path.parent.mkdir(parents=True, exist_ok=True)
        self.enabled = settings.honeytrace.response.enabled
        self.lock = threading.Lock()
        self.actions_proposed = 0
        self.actions_applied = 0
        self.actions_refused = 0
        self.last_error: Optional[str] = None

    @property
    def dry_run(self) -> bool:
        """Always read live: the operator may flip dry-run between actions."""
        return self.settings.honeytrace.response.dry_run

    # -- main entry ---------------------------------------------------------- #

    def evaluate(
        self,
        match: RuleMatch,
        incident: Optional[Incident] = None,
        event: Optional[Dict[str, Any]] = None,
    ) -> Optional[ResponseActionRecord]:
        """Evaluate the response policy for one rule match.

        Returns the action record (proposed/dry_run/applied/failed) or None
        when the policy is log-only-by-default with nothing to record.
        """
        if not self.enabled:
            return None
        actor = (event or {}).get("actor") or (incident.actor if incident else {}) or {}
        record = ResponseActionRecord(
            action_id=uuid.uuid4().hex,
            incident_id=incident.incident_id if incident else None,
            rule_id=match.rule_id,
            action=match.response_policy,
            status="proposed",
            target=self._target_of(match, actor),
            reason=match.explanation,
        )
        self.actions_proposed += 1

        # Gate 1: trusted-owner bypass.
        if self._is_trusted(actor):
            record.status = "proposed"
            record.reason = f"trusted owner bypass: {self._trust_reason(actor)}"
            record.rollback_result = "no action taken (trusted identity)"
            self._record(record)
            return record

        # Gate 2: containment-class actions need contain mode + arming.
        if match.response_policy in ("isolate", "throttle"):
            if self.arming.mode != "contain" or not self.arming.containment_armed:
                self.actions_refused += 1
                record.status = "proposed"
                record.reason += " | NOT APPLIED: containment not armed (arm --mode contain --confirm)"
                self._record(record)
                return record
            if self.dry_run:
                record.status = "dry_run"
                record.reason += " | dry-run: no state changed"
                self._record(record)
                return record
            return self._apply_containment(record, actor)

        # alert / log actions are always safe to apply.
        record.status = "applied" if match.response_policy == "alert" else "proposed"
        self._record(record)
        return record

    # -- containment ---------------------------------------------------------- #

    def _apply_containment(self, record: ResponseActionRecord, actor: Dict[str, Any]) -> ResponseActionRecord:
        lab_uid = self._lab_uid()
        if lab_uid is None:
            self.actions_refused += 1
            record.status = "failed"
            record.reason += f" | lab user {self.settings.honeytrace.containment.lab_user} not resolvable"
            self._record(record)
            return record

        # Only contain the lab UID. An action aimed at a different UID is refused.
        actor_uid = actor.get("uid")
        if actor_uid is not None and actor_uid != lab_uid:
            self.actions_refused += 1
            record.status = "failed"
            record.reason += f" | target uid {actor_uid} is not the lab uid {lab_uid}; refusing"
            self._record(record)
            return record

        tag = record.incident_id or record.rule_id or record.action_id
        rec = self.firewall.apply_isolation(lab_uid, tag)
        record.action = rec.action
        record.status = rec.status
        record.previous_state = rec.previous_state
        record.rollback_cmd = rec.rollback_cmd
        record.applied_at_utc = rec.applied_at_utc
        if rec.status == "applied":
            self.actions_applied += 1
            self._append_rollback(record, lab_uid, tag)
        else:
            self.actions_refused += 1
        self._record(record)
        return record

    def _lab_uid(self) -> Optional[int]:
        try:
            import pwd

            return pwd.getpwnam(self.settings.honeytrace.containment.lab_user).pw_uid
        except (ImportError, KeyError):
            return None

    def _append_rollback(self, record: ResponseActionRecord, uid: int, tag: str) -> None:
        entry = {
            "action_id": record.action_id,
            "incident_id": record.incident_id,
            "kind": "firewall_rule",
            "backend": self.firewall.backend,
            "uid": uid,
            "tag": tag,
            "rollback_cmd": record.rollback_cmd,
            "applied_at_utc": record.applied_at_utc,
        }
        with self.lock:
            with self.rollback_path.open("a", encoding="utf-8") as fh:
                fh.write(canonical_json(entry) + "\n")

    # -- rollback / emergency -------------------------------------------------- #

    def rollback_all(self) -> Dict[str, Any]:
        """Undo every applied containment change, newest first. Idempotent."""
        summary: Dict[str, Any] = {"rolled_back": 0, "already_absent": 0, "failed": 0, "entries": []}
        if not self.rollback_path.exists():
            return summary
        entries: List[Dict[str, Any]] = []
        for line in self.rollback_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        done_ids = set()
        for entry in reversed(entries):
            if entry.get("kind") != "firewall_rule":
                continue
            if entry["action_id"] in done_ids:
                continue
            done_ids.add(entry["action_id"])
            ok, msg = self.firewall.remove_rule(entry["uid"], entry["tag"])
            if ok and "already absent" in msg:
                summary["already_absent"] += 1
            elif ok:
                summary["rolled_back"] += 1
            else:
                summary["failed"] += 1
            summary["entries"].append({"action_id": entry["action_id"], "result": msg})
        return summary

    def emergency_off(self) -> Dict[str, Any]:
        """Stop new actions FIRST, then roll back HoneyTrace's own changes."""
        self.enabled = False
        self.arming.set_state("stopping")
        self.arming.disarm()
        summary = self.rollback_all()
        self.arming.set_state("disarmed")
        return summary

    # -- helpers --------------------------------------------------------------- #

    def _is_trusted(self, actor: Dict[str, Any]) -> bool:
        return bool(self._trust_reason(actor))

    def _trust_reason(self, actor: Dict[str, Any]) -> str:
        cfg = self.settings.honeytrace.response
        username = actor.get("username")
        if username and username in cfg.trusted_users:
            return f"user {username} is in trusted_users"
        tty = actor.get("tty")
        if tty and tty in cfg.maintenance_sessions:
            return f"session {tty} is a maintenance session"
        ip = actor.get("source_ip")
        if ip:
            for cidr in self.settings.networks.trusted_networks:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                        return f"source {ip} is in trusted network {cidr}"
                except ValueError:
                    continue
        return ""

    def _target_of(self, match: RuleMatch, actor: Dict[str, Any]) -> str:
        if actor.get("uid") is not None:
            return f"uid:{actor['uid']}"
        if actor.get("source_ip"):
            return f"ip:{actor['source_ip']}"
        return match.rule_id

    def _record(self, record: ResponseActionRecord) -> None:
        """Every decision (including refusals) lands in the evidence journal."""
        if self.journal is None:
            return
        from honeytrace.models.events import utc_now_iso

        self.journal.append(
            {
                "event_type": "response.action",
                "source": "response",
                "timestamp_utc": utc_now_iso(),
                "details": {
                    "action_id": record.action_id,
                    "action": record.action,
                    "status": record.status,
                    "target": record.target,
                    "rule_id": record.rule_id,
                    "incident_id": record.incident_id,
                    "reason": record.reason,
                    "rollback_cmd": record.rollback_cmd,
                },
                "observation": "observed",
                "confidence": 1.0,
            }
        )
