"""Unit tests: configuration loading and safety validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from honeytrace.config import ConfigError, load_settings, parse_rules
from tests.conftest import make_settings


def test_real_project_config_loads():
    """The shipped config/ tree must validate as-is (root = project dir)."""
    root = Path(__file__).resolve().parents[2]
    settings = load_settings(root, strict=False)
    problems = settings.validate()
    # The shipped config must be structurally sound; path problems on a
    # foreign machine (missing lab dirs) are allowed to be reported but the
    # shipped defaults are designed to be creatable.
    assert settings.rules, "rules.yml parsed to nothing"
    assert all(p.startswith("R-") for p in [r.id for r in settings.rules])
    # data dir creation is part of validate(); on a read-only CI this can
    # fail, so only structural problems block here.
    assert not [p for p in problems if "rules" in p.lower()]


def test_settings_rejects_system_monitored_path(tmp_path):
    s = make_settings(tmp_path, monitored=["/etc"])
    problems = s.validate()
    assert any("system path" in p for p in problems)


def test_settings_rejects_root_monitored_path(tmp_path):
    s = make_settings(tmp_path, monitored=["/"])
    problems = s.validate()
    assert any("root" in p for p in problems)


def test_settings_data_dir_created_and_writable(tmp_path):
    s = make_settings(tmp_path)
    problems = s.validate()
    assert s.data_dir.exists()
    assert not any("writable" in p for p in problems)


def test_rules_must_be_unique_ids():
    body = yaml.safe_load(
        """
rules:
  - id: R-X-001
    name: a
    severity: low
    conditions:
      - all: [{ event_type: file.open }]
  - id: R-X-001
    name: b
    severity: low
    conditions:
      - all: [{ event_type: file.open }]
"""
    )
    with pytest.raises(ConfigError, match="duplicate rule IDs"):
        parse_rules(body)


def test_rules_reject_bad_severity():
    body = yaml.safe_load(
        """
rules:
  - id: R-X-002
    name: a
    severity: catastrophic
    conditions:
      - all: [{ event_type: file.open }]
"""
    )
    with pytest.raises(ConfigError, match="severity"):
        parse_rules(body)


def test_rules_reject_unknown_response_policy():
    body = yaml.safe_load(
        """
rules:
  - id: R-X-003
    name: a
    severity: low
    response: nuke
    conditions:
      - all: [{ event_type: file.open }]
"""
    )
    with pytest.raises(ConfigError, match="response"):
        parse_rules(body)


def test_rules_reject_bad_combinator():
    body = yaml.safe_load(
        """
rules:
  - id: R-X-004
    name: a
    severity: low
    conditions:
      - maybe: [{ event_type: file.open }]
"""
    )
    with pytest.raises(ConfigError):
        parse_rules(body)


def test_rules_reject_bad_id_format():
    body = yaml.safe_load(
        """
rules:
  - id: DECOY_RULE
    name: a
    severity: low
    conditions:
      - all: [{ event_type: file.open }]
"""
    )
    with pytest.raises(ConfigError, match="rule ID"):
        parse_rules(body)


def test_contain_mode_requires_lab_user(tmp_path):
    s = make_settings(tmp_path)
    s.honeytrace.mode = "contain"
    s.honeytrace.response.dry_run = False
    problems = s.check_mode_transition("contain")
    # On Linux without the lab user OR on non-POSIX this must complain.
    assert problems, "contain mode must refuse to arm without its preconditions"


def test_env_allowlist_never_accepts_credentials(tmp_path):
    s = make_settings(tmp_path)
    from honeytrace.config import ProcessConfig

    with pytest.raises(Exception):
        ProcessConfig(env_allowlist=["PASSWORD"])
