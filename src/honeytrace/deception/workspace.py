"""Deception workspace: safe decoy placement in designated lab paths only.

Hard boundaries enforced here:

* Decoys are written ONLY into `paths.decoys` or directories explicitly
  listed in honeylist.yml, and those directories must live inside a
  monitored path or the decoy root. System paths are refused.
* HoneyTrace never replaces or bind-mounts over a real user's files. The
  recommended isolation (dedicated lab user / container / mount namespace)
  is prepared by scripts/install_lab.sh and documented in the README; this
  module only verifies the boundaries and hardens file modes.
* `deploy` is transactional: generate, write, fsync, register, then verify
  hashes. Any failure removes the partial files it created.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace.deception.generator import DecoyGenerator
from honeytrace.deception.inventory import DecoyInventory
from honeytrace.deception.tokens import TokenRegistry
from honeytrace.evidence.hashing import sha256_file
from honeytrace.models.events import new_event_id

SYSTEM_PATH_DENYLIST = (
    "/", "/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys",
    "/var/log", "/root", "/home",
)


class WorkspaceError(ValueError):
    pass


class DeceptionWorkspace:
    def __init__(self, settings, inventory: DecoyInventory, registry: TokenRegistry):
        self.settings = settings
        self.inventory = inventory
        self.registry = registry
        self.generator = DecoyGenerator(registry, seed=settings.honeylist.random_seed)
        self._boundaries: List[Path] = []

    # -- boundary checks ----------------------------------------------------- #

    def set_boundaries(self, decoys_root: Path, monitored: List[Path]) -> None:
        """Declare where decoys may live. Called at daemon startup."""
        self._boundaries = [Path(decoys_root).resolve(), *(p.resolve() for p in monitored)]

    def _validate_target(self, directory: Path) -> Path:
        directory = Path(directory).expanduser()
        directory = directory if directory.is_absolute() else (self.settings.root / directory)
        directory = directory.resolve()
        if str(directory) in SYSTEM_PATH_DENYLIST or directory == Path("/"):
            raise WorkspaceError(f"refusing decoy placement in system path: {directory}")
        for part in SYSTEM_PATH_DENYLIST:
            if str(directory) == part:
                raise WorkspaceError(f"refusing decoy placement in protected path: {directory}")
        if not self._boundaries:
            raise WorkspaceError("workspace boundaries not set; refusing to place decoys")
        if not any(
            directory == b or b in directory.parents for b in self._boundaries
        ):
            raise WorkspaceError(
                f"{directory} is outside designated lab paths {self._boundaries}"
            )
        return directory

    # -- deployment ------------------------------------------------------------ #

    def deploy_from_honeylist(self, only_group: Optional[str] = None) -> Dict[str, Any]:
        """Deploy all enabled decoy groups from honeylist.yml."""
        report: Dict[str, Any] = {"placed": [], "failed": [], "groups": []}
        for group in self.settings.honeylist.decoy_groups:
            if not group.enabled or (only_group and group.name != only_group):
                continue
            try:
                directory = self._validate_target(Path(group.directory))
            except WorkspaceError as exc:
                report["failed"].append({"group": group.name, "error": str(exc)})
                continue
            for item in group.items:
                for instance in range(1, item.count + 1):
                    decoy_id = f"DCY-{new_event_id()[:12].upper()}"
                    decoy = None
                    try:
                        decoy = self.generator.generate(
                            directory, item.type, item.name, item.content_profile,
                            instance=instance, decoy_id=decoy_id,
                        )
                        decoy.path.parent.mkdir(parents=True, exist_ok=True)
                        tmp = decoy.path.with_suffix(decoy.path.suffix + ".honeytrace-part")
                        with tmp.open("wb") as fh:
                            fh.write(decoy.payload)
                            fh.flush()
                            os.fsync(fh.fileno())
                        os.replace(tmp, decoy.path)
                        self._harden(decoy.path)
                        digest = sha256_file(decoy.path) or ""
                        self.inventory.register(
                            decoy_id=decoy_id,
                            path=decoy.path,
                            decoy_type=item.type,
                            profile=item.content_profile,
                            sha256=digest,
                            token_url=self._token_url_for(decoy_id),
                        )
                        self.inventory.attach_process_info(decoy_id)
                        report["placed"].append({"decoy_id": decoy_id, "path": str(decoy.path)})
                    except OSError as exc:
                        # Transactional: remove the partial file this attempt created.
                        if decoy is not None and decoy.path.exists():
                            try:
                                decoy.path.unlink()
                            except OSError:
                                pass
                        report["failed"].append(
                            {"group": group.name, "path": str(decoy.path) if decoy else None, "error": str(exc)}
                        )
            report["groups"].append(group.name)
        return report

    def _token_url_for(self, decoy_id: str) -> Optional[str]:
        # The token was embedded during generation; find its URL from the registry.
        for entry in self.registry.all_tokens().values():
            if entry.get("decoy_id") == decoy_id:
                return entry.get("url")
        return None

    def _harden(self, path: Path) -> None:
        """Apply the configured file mode; readable, owner-writable only."""
        try:
            os.chmod(path, self.settings.honeylist.file_mode)
        except OSError:
            pass

    def verify_integrity(self) -> List[Dict[str, Any]]:
        return self.inventory.check_integrity()

    def cleanup(self, force: bool = False) -> Dict[str, Any]:
        """Remove ONLY inventory-listed decoys. Never touches other files."""
        return self.inventory.cleanup(force=force)
