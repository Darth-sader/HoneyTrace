"""Actor, process and target reference models.

Everything here distinguishes *observed* values (directly read from the OS)
from *inferred* ones (correlated, enriched, or guessed). Fields that could
not be collected are left absent (None) - never zero and never fabricated.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ActorRef(BaseModel):
    """Who the OS says performed an action - not who the human is."""

    model_config = ConfigDict(extra="forbid")

    uid: Optional[int] = None
    gid: Optional[int] = None
    username: Optional[str] = None
    session_id: Optional[str] = None       # audit session id or session UUID
    tty: Optional[str] = None
    source_ip: Optional[str] = None
    auth_method: Optional[str] = None      # ssh | local | sudo | su | unknown
    # "observed" (read from the OS), "inferred" (correlated) or "unknown"
    attribution: str = "unknown"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ProcessRef(BaseModel):
    """A process snapshot taken at (or near) event time."""

    model_config = ConfigDict(extra="forbid")

    pid: Optional[int] = None
    ppid: Optional[int] = None
    # Process start time (epoch seconds) - guards against PID reuse.
    start_time: Optional[float] = None
    exe: Optional[str] = None
    cmdline: List[str] = Field(default_factory=list)
    cwd: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    terminal: Optional[str] = None
    # parent chain as [("pid", "exe"), ...] nearest parent first
    ancestry: List[List[str]] = Field(default_factory=list)
    # psutil | linux-audit | proc-scan | unknown
    source: str = "unknown"
    # Resource/descriptor snapshot when permissions allowed it.
    cpu_percent: Optional[float] = None
    rss_bytes: Optional[int] = None
    num_threads: Optional[int] = None
    num_fds: Optional[int] = None
    status: Optional[str] = None


class FileTarget(BaseModel):
    """The file (or directory) an event applies to."""

    model_config = ConfigDict(extra="forbid")

    path: str
    exists: Optional[bool] = None
    size: Optional[int] = None
    inode: Optional[int] = None
    sha256: Optional[str] = None
    is_decoy: bool = False
    decoy_id: Optional[str] = None
    # "file" | "dir" | "symlink" | "unknown"
    kind: str = "file"


class NetworkEnrichment(BaseModel):
    """Enrichment context for an endpoint. Always inferred, time-stamped."""

    model_config = ConfigDict(extra="forbid")

    reverse_dns: Optional[str] = None
    geoip_country: Optional[str] = None
    geoip_city: Optional[str] = None
    asn_number: Optional[int] = None
    asn_org: Optional[str] = None
    rdap_netname: Optional[str] = None
    rdap_country: Optional[str] = None
    # Which enrichment source answered, and when.
    sources: List[str] = Field(default_factory=list)
    updated_utc: Optional[str] = None
    approximate: bool = True


class NetEndpoint(BaseModel):
    """A socket observation."""

    model_config = ConfigDict(extra="forbid")

    family: str = "ipv4"                   # ipv4 | ipv6 | unix
    proto: str = "tcp"                     # tcp | udp | unix
    local_addr: Optional[str] = None
    local_port: Optional[int] = None
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    status: Optional[str] = None           # ESTABLISHED, SYN_SENT, LISTEN ...
    direction: str = "unknown"             # inbound | outbound | local
    # Ownership is only recorded when actually observed.
    owner_pid: Optional[int] = None
    owner_process: Optional[str] = None
    # "observed" | "denied" | "ambiguous" | "unknown"
    ownership: str = "unknown"
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    enrichment: Optional[NetworkEnrichment] = None
