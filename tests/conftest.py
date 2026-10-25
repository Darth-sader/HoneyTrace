"""Shared pytest fixtures.

Adds src/ to sys.path so the suite runs without installing the package
(the Linux lab installs it with `pip install -e .` either way), and builds
an isolated Settings object rooted in a tmp directory for every test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from honeytrace.config import (  # noqa: E402
    HoneytraceConfig,
    Settings,
    parse_rules,
)

RULES_YAML = """
rules:
  - id: R-DECOY-001
    name: Decoy file accessed
    description: test
    enabled: true
    severity: high
    confidence_weight: 0.7
    mitre: [T1083]
    conditions:
      - any:
          - { event_type: file.open, target_is_decoy: true }
    group_by: session_id
    threshold: 1
    window_seconds: 600
    suppression_seconds: 0
    response: alert

  - id: R-BULK-002
    name: Bulk file enumeration
    description: test
    enabled: true
    severity: medium
    confidence_weight: 0.6
    mitre: [T1083]
    conditions:
      - any:
          - { event_type: file.open }
          - { event_type: file.access }
    group_by: session_id
    threshold: 5
    window_seconds: 10
    suppression_seconds: 0
    response: alert

  - id: R-SEQ-003
    name: Ordered recon sequence
    description: test
    enabled: true
    severity: medium
    confidence_weight: 0.6
    mitre: [T1033]
    conditions:
      - sequence:
          - { event_type: exec.command, process_name: whoami }
          - { event_type: exec.command, process_name: id }
    group_by: session_id
    threshold: 1
    window_seconds: 120
    suppression_seconds: 0
    response: alert

  - id: R-NET-008
    name: Unexpected outbound destination
    description: test
    enabled: true
    severity: medium
    confidence_weight: 0.55
    mitre: [T1041]
    conditions:
      - any:
          - { event_type: net.connection, details_field: allowlisted, details_value: false }
    group_by: session_id
    threshold: 1
    window_seconds: 600
    suppression_seconds: 0
    response: alert

  - id: R-EXFIL-011
    name: Suspected staged exfiltration
    description: test
    enabled: true
    severity: critical
    confidence_weight: 0.7
    mitre: [T1074.001, T1041]
    conditions:
      - sequence:
          - { event_type: file.create, target_path_prefix: "/tmp" }
          - { event_type: net.connection, details_field: direction, details_value: outbound }
    group_by: session_id
    threshold: 1
    window_seconds: 600
    suppression_seconds: 0
    response: isolate
"""


def make_settings(tmp_path: Path, monitored: list | None = None) -> Settings:
    """Settings rooted at tmp_path with a tmp data dir - nothing leaks out."""
    settings = Settings(tmp_path)
    settings.honeytrace = HoneytraceConfig()
    settings.honeytrace.paths.monitored = monitored or [str(tmp_path / "lab" / "docs")]
    settings.honeytrace.paths.data = str(tmp_path / "data")
    settings.honeytrace.paths.logs = str(tmp_path / "data" / "logs")
    settings.honeytrace.paths.decoys = str(tmp_path / "decoys")
    settings.rules = parse_rules(yaml.safe_load(RULES_YAML))
    settings.honeylist.random_seed = 1234
    # Mirror the shipped networks.yml trusted list (defaults are empty).
    settings.networks.trusted_networks = ["127.0.0.0/8", "::1/128", "192.168.0.0/16", "10.0.0.0/8"]
    return settings


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    s = make_settings(tmp_path)
    s.data_dir.mkdir(parents=True, exist_ok=True)
    return s


@pytest.fixture()
def decoy_inventory(settings):
    from honeytrace.deception.inventory import DecoyInventory

    return DecoyInventory(settings.data_dir)


def make_decoy(settings: Settings, inventory, name: str = "bait.txt") -> Path:
    """Create one registered decoy file for tests."""
    path = settings.data_dir / "decoys_test" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = b"HoneyTrace synthetic decoy\nbeacon: http://127.0.0.1:8099/beacon/abc\n"
    path.write_bytes(payload)
    import hashlib

    decoy_id = f"DCY-TEST-{abs(hash(name)) % 10000:04d}"
    inventory.register(
        decoy_id=decoy_id, path=path, decoy_type="txt", profile="notes",
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    return path
