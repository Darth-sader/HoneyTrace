"""Typed configuration loading and validation.

Five YAML files feed HoneyTrace:

    config/honeytrace.yml  - main operator configuration (modes, paths, sensors)
    config/rules.yml       - detection rules
    config/networks.yml    - trusted networks, allowlists, exclusions
    config/honeylist.yml   - decoy generation definitions
    config/retention.yml   - evidence retention and disk safeguards

All path handling uses pathlib. Relative paths resolve against the project
root (the directory that contains `config/`), never the user's home
directory. Validation is deliberately strict: an unsafe configuration is
rejected before anything is armed.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from honeytrace.models.incidents import SEVERITY_ORDER

CONFIG_DIRNAME = "config"
SYSTEM_PATH_DENYLIST = (
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/dev", "/proc", "/sys", "/var/log", "/root",
    "/etc/passwd", "/etc/shadow",
)

RULE_ID_RE = re.compile(r"^R-[A-Z0-9]+-\d{3}$")
RESPONSE_POLICIES = ("log", "alert", "isolate", "throttle")
GROUP_KEYS = ("session_id", "actor", "source_ip", "process", "global")
MODES = ("observe", "deceive", "contain")


def find_project_root(start: Optional[Path] = None) -> Path:
    """Walk up from `start` (default: cwd) looking for a config/ directory."""
    env = os.environ.get("HONEYTRACE_HOME")
    if env:
        return Path(env).expanduser().resolve()
    cur = (start or Path.cwd()).resolve()
    for candidate in (cur, *cur.parents):
        if (candidate / CONFIG_DIRNAME).is_dir():
            return candidate
    # Fall back to the package layout (src/honeytrace -> project root).
    pkg_root = Path(__file__).resolve().parents[3]
    if (pkg_root / CONFIG_DIRNAME).is_dir():
        return pkg_root
    return cur


class ConfigError(ValueError):
    """Raised for malformed or unsafe configuration."""


# --------------------------------------------------------------------------- #
# Main configuration
# --------------------------------------------------------------------------- #

class PathsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    monitored: List[str] = Field(default_factory=list)
    decoys: str = "./decoys"
    data: str = "./data"
    logs: str = "./data/logs"


class DetectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bulk_access_window_seconds: int = Field(default=10, gt=0)
    bulk_access_threshold: int = Field(default=20, ge=2)
    odd_hours_enabled: bool = False
    odd_hours_start: str = "23:00"
    odd_hours_end: str = "06:00"
    incident_gap_seconds: int = Field(default=900, gt=0)
    dedup_window_seconds: float = Field(default=2.0, ge=0)


class NetworkConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pcap_enabled: bool = False
    pcap_interface: str = "eth0"
    pcap_rotate_seconds: int = Field(default=10, gt=0)
    pcap_ring_count: int = Field(default=12, ge=2, le=64)
    pcap_snaplen: int = Field(default=96, ge=16)
    canary_enabled: bool = False
    canary_host: str = "127.0.0.1"
    canary_port: int = Field(default=8099, gt=0, lt=65536)
    reverse_dns_enabled: bool = True
    geoip_db_path: Optional[str] = None
    asn_db_path: Optional[str] = None
    rdap_enabled: bool = False

    @model_validator(mode="after")
    def _warn_host(self) -> "NetworkConfig":
        # Non-loopback canary binding is allowed but must be deliberate.
        if self.canary_host not in ("127.0.0.1", "localhost", "::1"):
            import logging

            logging.getLogger("honeytrace.config").warning(
                "canary_host is %s (non-loopback); ensure this is an isolated lab interface",
                self.canary_host,
            )
        return self


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    log_file: str = "/var/log/audit/audit.log"
    key: str = "honeytrace"


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    source: str = "auto"  # auto | journal | file
    auth_log: str = "/var/log/auth.log"
    failed_login_window_seconds: int = Field(default=60, gt=0)
    failed_login_threshold: int = Field(default=5, ge=2)

    @field_validator("source")
    @classmethod
    def _check_source(cls, v: str) -> str:
        if v not in ("auto", "journal", "file"):
            raise ConfigError(f"auth.source must be auto|journal|file, got {v!r}")
        return v


class ProcessConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    scan_interval_seconds: float = Field(default=2.0, gt=0)
    env_allowlist: List[str] = Field(
        default_factory=lambda: ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "USER", "HOME", "LANG", "TERM"]
    )

    @field_validator("env_allowlist")
    @classmethod
    def _deny_secret_env(cls, names: List[str]) -> List[str]:
        forbidden = {"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "AWS_SECRET_ACCESS_KEY"}
        bad = [n for n in names if n.upper() in forbidden]
        if bad:
            raise ConfigError(f"env_allowlist must never include credential variables: {bad}")
        return names


class ResponseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    dry_run: bool = True
    require_confirmation: bool = True
    trusted_users: List[str] = Field(default_factory=list)
    maintenance_sessions: List[str] = Field(default_factory=list)


class ContainmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lab_user: str = "labuser"
    firewall_backend: str = "iptables"  # iptables | nft
    throttle_cpu_quota: int = Field(default=20, ge=1, le=100)

    @field_validator("firewall_backend")
    @classmethod
    def _check_backend(cls, v: str) -> str:
        if v not in ("iptables", "nft"):
            raise ConfigError(f"containment.firewall_backend must be iptables|nft, got {v!r}")
        return v


class HealthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_interval_seconds: int = Field(default=15, gt=0)
    low_disk_warn_percent: int = Field(default=80, ge=1, le=99)
    queue_warn_depth: int = Field(default=5000, gt=0)


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: str = "INFO"
    rotate_when_mb: int = Field(default=10, gt=0)
    keep_files: int = Field(default=5, ge=1)


class HoneytraceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: str = "observe"
    paths: PathsConfig = Field(default_factory=PathsConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    process: ProcessConfig = Field(default_factory=ProcessConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    containment: ContainmentConfig = Field(default_factory=ContainmentConfig)
    health: HealthConfig = Field(default_factory=HealthConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        if v not in MODES:
            raise ConfigError(f"mode must be one of {MODES}, got {v!r}")
        return v


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

class RuleCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_types: frozenset[str] = frozenset()
    target_is_decoy: Optional[bool] = None
    target_path_prefix: Optional[str] = None
    process_name: Optional[str] = None
    actor_uid: Optional[int] = None
    actor_username: Optional[str] = None
    source_ip: Optional[str] = None
    details_field: Optional[str] = None
    details_value: Any = None

    def describe(self) -> str:
        parts = []
        if self.event_types:
            parts.append("event_type in {" + ", ".join(sorted(self.event_types)) + "}")
        if self.target_is_decoy is not None:
            parts.append(f"target_is_decoy={self.target_is_decoy}")
        if self.target_path_prefix:
            parts.append(f"path~{self.target_path_prefix}")
        if self.process_name:
            parts.append(f"process={self.process_name}")
        if self.details_field:
            parts.append(f"{self.details_field}=={self.details_value!r}")
        if self.actor_username:
            parts.append(f"actor={self.actor_username}")
        if self.source_ip:
            parts.append(f"source={self.source_ip}")
        return " AND ".join(parts) if parts else "any event"


class RuleGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str  # all | any | sequence
    conditions: List[RuleCondition]

    @field_validator("kind")
    @classmethod
    def _check_kind(cls, v: str) -> str:
        if v not in ("all", "any", "sequence"):
            raise ConfigError(f"condition combinator must be all|any|sequence, got {v!r}")
        return v


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str = ""
    enabled: bool = True
    severity: str
    confidence_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    mitre: List[str] = Field(default_factory=list)
    conditions: List[RuleGroup]
    group_by: str = "session_id"
    threshold: int = Field(default=1, ge=1)
    window_seconds: int = Field(default=600, gt=0)
    suppression_seconds: int = Field(default=0, ge=0)
    response: str = "alert"

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        if v not in SEVERITY_ORDER:
            raise ConfigError(f"rule severity must be one of {tuple(SEVERITY_ORDER)}, got {v!r}")
        return v

    @field_validator("response")
    @classmethod
    def _check_response(cls, v: str) -> str:
        if v not in RESPONSE_POLICIES:
            raise ConfigError(f"rule response must be one of {RESPONSE_POLICIES}, got {v!r}")
        return v

    @field_validator("group_by")
    @classmethod
    def _check_group_by(cls, v: str) -> str:
        if v not in GROUP_KEYS:
            raise ConfigError(f"rule group_by must be one of {GROUP_KEYS}, got {v!r}")
        return v


class RulesFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: List[Rule]


def _parse_condition(raw: Dict[str, Any]) -> RuleCondition:
    if not isinstance(raw, dict):
        raise ConfigError(f"rule condition must be a mapping, got {raw!r}")
    types_raw = raw.get("event_type", raw.get("event_types"))
    types: tuple = ()
    if types_raw is not None:
        if isinstance(types_raw, str):
            types = (types_raw,)
        elif isinstance(types_raw, list):
            types = tuple(types_raw)
        else:
            raise ConfigError(f"event_type must be a string or list: {types_raw!r}")
    return RuleCondition(
        event_types=frozenset(types),
        target_is_decoy=raw.get("target_is_decoy"),
        target_path_prefix=raw.get("target_path_prefix"),
        process_name=raw.get("process_name"),
        actor_uid=raw.get("actor_uid"),
        actor_username=raw.get("actor_username"),
        source_ip=raw.get("source_ip"),
        details_field=raw.get("details_field"),
        details_value=raw.get("details_value"),
    )


def parse_rules(data: Dict[str, Any]) -> List[Rule]:
    """Parse and validate the rules.yml body. Raises ConfigError on problems."""
    try:
        doc = RulesFile.model_validate(
            {
                "rules": [
                    {
                        **r,
                        "conditions": [
                            {
                                "kind": kind,
                                "conditions": [_parse_condition(c) for c in conds],
                            }
                            for grp in r.get("conditions", [])
                            for kind, conds in grp.items()
                        ],
                    }
                    for r in data.get("rules", [])
                ]
            }
        )
    except Exception as exc:  # pydantic ValidationError -> stable message
        raise ConfigError(f"invalid rules.yml: {exc}") from exc

    ids = [r.id for r in doc.rules]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        raise ConfigError(f"duplicate rule IDs: {dupes}")
    for rid in ids:
        if not RULE_ID_RE.match(rid):
            raise ConfigError(f"rule ID {rid!r} does not match pattern {RULE_ID_RE.pattern}")
    return doc.rules


# --------------------------------------------------------------------------- #
# Networks / honeylist / retention
# --------------------------------------------------------------------------- #

class NetworkEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None


class NetworksConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trusted_networks: List[str] = Field(default_factory=list)
    expected_destinations: List[NetworkEntry] = Field(default_factory=list)
    local_services: List[Dict[str, Any]] = Field(default_factory=list)
    excluded_processes: List[str] = Field(default_factory=list)
    lab_network: Optional[str] = None


class DecoyItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    name: str
    count: int = Field(default=1, ge=1)
    content_profile: str = "generic"


class DecoyGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    directory: str
    enabled: bool = True
    items: List[DecoyItem] = Field(default_factory=list)


class HoneylistConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decoy_groups: List[DecoyGroup] = Field(default_factory=list)
    file_mode: int = 0o644
    embed_tokens: bool = True
    random_seed: Optional[int] = None

    @field_validator("file_mode", mode="before")
    @classmethod
    def _parse_file_mode(cls, v):
        """Accept 0o644 (int), '0o644' or '644' (YAML 1.1 keeps 0o-prefixed
        octal as a string) and normalize to an integer mode."""
        if isinstance(v, str):
            s = v.strip()
            if s.lower().startswith("0o"):
                return int(s, 8)
            if s.isdigit():
                return int(s, 8)  # mode-like strings are octal
            raise ConfigError(f"file_mode must be octal like 0644, got {v!r}")
        return v


class RetentionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    class Journal(BaseModel):
        model_config = ConfigDict(extra="forbid")
        max_segment_mb: int = Field(default=50, gt=0)
        max_segments: int = Field(default=20, ge=1)
        checkpoint_every: int = Field(default=500, ge=0)

    class Pcap(BaseModel):
        model_config = ConfigDict(extra="forbid")
        max_total_mb: int = Field(default=200, gt=0)
        max_files: int = Field(default=12, ge=1)

    class Reports(BaseModel):
        model_config = ConfigDict(extra="forbid")
        keep_reports: int = Field(default=20, ge=1)

    class Manifest(BaseModel):
        model_config = ConfigDict(extra="forbid")
        max_segment_mb: int = Field(default=20, gt=0)
        max_segments: int = Field(default=10, ge=1)

    class Quota(BaseModel):
        model_config = ConfigDict(extra="forbid")
        data_dir_max_mb: int = Field(default=2048, gt=0)
        free_space_warn_percent: int = Field(default=15, ge=1, le=99)
        sweep_interval_seconds: int = Field(default=300, gt=0)

    class ExportCfg(BaseModel):
        model_config = ConfigDict(extra="forbid")
        approved_artifact_suffixes: List[str] = Field(default_factory=list)

    journal: Journal = Field(default_factory=Journal)
    pcap: Pcap = Field(default_factory=Pcap)
    reports: Reports = Field(default_factory=Reports)
    manifest: Manifest = Field(default_factory=Manifest)
    quota: Quota = Field(default_factory=Quota)
    export: ExportCfg = Field(default_factory=ExportCfg)


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #

class Settings:
    """Fully resolved configuration bundle."""

    def __init__(self, root: Path):
        self.root = root
        self.config_dir = root / CONFIG_DIRNAME
        self.honeytrace: HoneytraceConfig = HoneytraceConfig()
        self.rules: List[Rule] = []
        self.networks: NetworksConfig = NetworksConfig()
        self.honeylist: HoneylistConfig = HoneylistConfig()
        self.retention: RetentionConfig = RetentionConfig()

    # -- path helpers ------------------------------------------------------- #

    def resolve_path(self, raw: str) -> Path:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (self.root / p).resolve()
        else:
            p = p.resolve()
        return p

    @property
    def data_dir(self) -> Path:
        return self.resolve_path(self.honeytrace.paths.data)

    @property
    def decoys_dir(self) -> Path:
        return self.resolve_path(self.honeytrace.paths.decoys)

    @property
    def logs_dir(self) -> Path:
        return self.resolve_path(self.honeytrace.paths.logs)

    def monitored_paths(self) -> List[Path]:
        return [self.resolve_path(p) for p in self.honeytrace.paths.monitored]

    # -- validation --------------------------------------------------------- #

    def validate(self) -> List[str]:
        """Full validation. Returns a list of human-readable problems.

        Empty list = safe to arm. Structural problems already raised
        ConfigError during parsing; these are semantic/safety checks.
        """
        problems: List[str] = []

        # Safe path boundaries. Check the RAW configured strings first (this
        # works regardless of platform path resolution), then resolved paths.
        for raw in self.honeytrace.paths.monitored:
            if raw == "/":
                problems.append("monitored path must not be the filesystem root (/)")
            elif raw in SYSTEM_PATH_DENYLIST:
                problems.append(f"monitored path {raw} is a protected system path - refuse to monitor")
        for p in self.monitored_paths():
            if p == Path("/"):
                problems.append("monitored path must not be the filesystem root (/)")
            elif str(p) in SYSTEM_PATH_DENYLIST:
                problems.append(f"monitored path {p} is a protected system path - refuse to monitor")

        decoys = self.decoys_dir
        if str(decoys) in SYSTEM_PATH_DENYLIST or decoys == Path("/"):
            problems.append(f"decoys path {decoys} is unsafe")

        data = self.data_dir
        if str(data) in SYSTEM_PATH_DENYLIST or data == Path("/"):
            problems.append(f"data path {data} is unsafe")
        if data.exists() and not data.is_dir():
            problems.append(f"data path {data} exists but is not a directory")

        # Writable storage (create if missing so first run works).
        try:
            data.mkdir(parents=True, exist_ok=True)
            probe = data / ".honeytrace_write_probe"
            probe.write_text("ok")
            probe.unlink()
        except OSError as exc:
            problems.append(f"data directory {data} is not writable: {exc}")

        # Rules sanity that parsing cannot express.
        active = [r for r in self.rules if r.enabled]
        if not active:
            problems.append("no enabled rules - the engine would never raise an incident")
        for rule in self.rules:
            if rule.response in ("isolate", "throttle") and not rule.enabled:
                continue
            if rule.severity not in SEVERITY_ORDER:
                problems.append(f"rule {rule.id}: unknown severity {rule.severity}")
            if rule.confidence_weight > 1.0:
                problems.append(f"rule {rule.id}: confidence_weight > 1.0")
            if rule.response in ("isolate", "throttle") and self.honeytrace.mode == "observe":
                # Allowed: response engine turns these into logged proposals.
                pass

        # Unsafe containment settings.
        if self.honeytrace.mode == "contain":
            if self.honeytrace.containment.lab_user in ("root", "", None):
                problems.append("containment.lab_user must be a dedicated non-root lab user")
            if self.honeytrace.response.dry_run:
                problems.append(
                    "mode=contain with response.dry_run=true: containment will only be simulated"
                )

        # canary destination sanity
        if self.honeytrace.network.canary_enabled and self.honeytrace.network.canary_port == 0:
            problems.append("canary_enabled with port 0 is invalid")

        return problems

    def check_mode_transition(self, new_mode: str) -> List[str]:
        """Extra checks when the operator arms a specific mode."""
        problems: List[str] = []
        if new_mode == "contain":
            lab = self.honeytrace.containment.lab_user
            try:
                import pwd  # POSIX only

                pwd.getpwnam(lab)
            except ImportError:
                problems.append("contain mode requires POSIX (Linux) to resolve the lab user")
            except KeyError:
                problems.append(
                    f"contain mode requires lab user {lab!r} to exist - run scripts/install_lab.sh"
                )
            if self.honeytrace.containment.firewall_backend == "nft":
                if not _which("nft"):
                    problems.append("firewall_backend=nft but nft(8) not found in PATH")
            elif not _which("iptables"):
                problems.append("firewall_backend=iptables but iptables(8) not found in PATH")
        return problems


def _which(cmd: str) -> Optional[str]:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = Path(d) / cmd
        try:
            if p.exists() and (p.stat().st_mode & stat.S_IXUSR):
                return str(p)
        except OSError:
            continue
    return None


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"configuration file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML syntax error in {path.name}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} must contain a YAML mapping, got {type(data).__name__}")
    return data


def load_settings(root: Optional[Path] = None, strict: bool = True) -> Settings:
    """Load all configuration files. Raises ConfigError when strict=True."""
    root = (root or find_project_root()).resolve()
    cfg_dir = root / CONFIG_DIRNAME
    settings = Settings(root)

    ht_raw = _load_yaml(cfg_dir / "honeytrace.yml")
    settings.honeytrace = HoneytraceConfig.model_validate(ht_raw)

    rules_raw = _load_yaml(cfg_dir / "rules.yml")
    settings.rules = parse_rules(rules_raw)

    settings.networks = NetworksConfig.model_validate(_load_yaml(cfg_dir / "networks.yml"))
    settings.honeylist = HoneylistConfig.model_validate(_load_yaml(cfg_dir / "honeylist.yml"))
    settings.retention = RetentionConfig.model_validate(_load_yaml(cfg_dir / "retention.yml"))

    if strict:
        problems = settings.validate()
        if problems:
            raise ConfigError(
                "configuration validation failed:\n  - " + "\n  - ".join(problems)
            )
    return settings


def summarize_problems(settings: Settings) -> Tuple[bool, List[str]]:
    """Non-raising validation for `honeytrace test-config` / `doctor`."""
    try:
        problems = settings.validate()
    except ConfigError as exc:
        return False, [str(exc)]
    return (not problems), problems
