"""Network socket collector with enrichment.

Snapshots socket tables periodically (psutil, with a documented permission
model: owning PIDs of other users' sockets require root/CAP_NET_ADMIN and
are recorded as 'denied' when unavailable - never guessed). New outbound/
inbound connections and listeners become net.connection / net.listen events.

Enrichment (reverse DNS, GeoIP, ASN, RDAP) runs asynchronously with caching
and short timeouts; enrichment is attached to events only when available and
is ALWAYS marked inferred + time-stamped. Enrichment is context, never
identity: an IP address does not name a person.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional, Set, Tuple

from honeytrace.collectors import STATUS_DISABLED, STATUS_ERROR, STATUS_OK, CollectorBase
from honeytrace.models.actors import NetworkEnrichment
from honeytrace.models.events import utc_now_iso

try:
    import psutil

    PSUTIL_OK = True
except ImportError:  # pragma: no cover
    PSUTIL_OK = False

ENRICH_TIMEOUT = 3.0
ENRICH_CACHE_TTL = 3600.0


class NetworkEnricher:
    """Async, cached enrichment with hard timeouts. Failure = absent field."""

    def __init__(self, settings):
        cfg = settings.honeytrace.network
        self.enabled = bool(cfg.reverse_dns_enabled or cfg.geoip_db_path or cfg.rdap_enabled)
        self.reverse_dns_enabled = cfg.reverse_dns_enabled
        self.rdap_enabled = cfg.rdap_enabled
        self.geoip_reader = None
        self.asn_reader = None
        if cfg.geoip_db_path:
            try:
                import maxminddb  # optional

                self.geoip_reader = maxminddb.open_database(cfg.geoip_db_path)
            except ImportError:
                self.geoip_reader = None
            except Exception:
                self.geoip_reader = None
        if cfg.asn_db_path:
            try:
                import maxminddb

                self.asn_reader = maxminddb.open_database(cfg.asn_db_path)
            except Exception:
                self.asn_reader = None
        self._cache: Dict[str, Tuple[float, Optional[NetworkEnrichment]]] = {}
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="honeytrace-enrich")
        self._inflight: Dict[str, object] = {}

    def submit(self, ip: str) -> None:
        """Start enrichment for an IP (idempotent, non-blocking)."""
        if not self.enabled or not ip or ip.startswith("127.") or ip == "::1":
            return
        cached = self._cache.get(ip)
        if cached and time.monotonic() - cached[0] < ENRICH_CACHE_TTL:
            return
        if ip in self._inflight:
            return
        fut = self._pool.submit(self._enrich, ip)
        self._inflight[ip] = fut

    def poll(self, ip: str) -> Optional[NetworkEnrichment]:
        """Return enrichment when ready; None while pending/unavailable."""
        cached = self._cache.get(ip)
        if cached and time.monotonic() - cached[0] < ENRICH_CACHE_TTL:
            return cached[1]
        fut = self._inflight.pop(ip, None)
        if fut is None:
            return None
        try:
            result = fut.result(timeout=0.01)
        except Exception:
            result = None
        self._cache[ip] = (time.monotonic(), result)
        return result

    # ------------------------------------------------------------------ #

    def _enrich(self, ip: str) -> Optional[NetworkEnrichment]:
        enr = NetworkEnrichment(updated_utc=utc_now_iso())
        sources: list = []

        if self.reverse_dns_enabled:
            name = self._reverse_dns(ip)
            if name:
                enr.reverse_dns = name
                sources.append("reverse-dns")

        if self.geoip_reader:
            try:
                rec = self.geoip_reader.get(ip) or {}
                country = ((rec.get("country") or {}).get("iso_code")) or (
                    (rec.get("registered_country") or {}).get("iso_code")
                )
                city = ((rec.get("city") or {}).get("names") or {}).get("en")
                if country:
                    enr.geoip_country = country
                if city:
                    enr.geoip_city = city
                sources.append("geoip-mmdb")
            except Exception:
                pass

        if self.asn_reader:
            try:
                rec = self.asn_reader.get(ip) or {}
                if rec.get("autonomous_system_number"):
                    enr.asn_number = rec["autonomous_system_number"]
                    enr.asn_org = rec.get("autonomous_system_organization")
                    sources.append("asn-mmdb")
            except Exception:
                pass

        if self.rdap_enabled:
            rdap = self._rdap(ip)
            if rdap:
                enr.rdap_netname = rdap.get("name")
                enr.rdap_country = rdap.get("country")
                sources.append("rdap")

        enr.sources = sources
        enr.approximate = True
        return enr if sources else None

    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError, UnicodeError):
            return None

    @staticmethod
    def _rdap(ip: str) -> Optional[Dict[str, Any]]:
        try:
            req = urllib.request.Request(
                f"https://rdap.org/ip/{ip}",
                headers={"User-Agent": "HoneyTrace-lab/2.0", "Accept": "application/rdap+json"},
            )
            with urllib.request.urlopen(req, timeout=ENRICH_TIMEOUT) as resp:
                import json as _json

                data = _json.loads(resp.read(65536).decode("utf-8", "replace"))
            return {"name": data.get("name"), "country": data.get("country")}
        except Exception:
            return None

    def close(self) -> None:
        self._pool.shutdown(wait=False)


class NetworkCollector(CollectorBase):
    name = "network"

    def __init__(self, emit, settings):
        super().__init__(emit, settings)
        self.settings = settings
        self.enricher = NetworkEnricher(settings)
        self.interval = 2.0
        self._prev: Dict[Tuple, Dict[str, Any]] = {}
        self._pending_enrich: Set[str] = set()
        self.denied_ownership = 0

        if not PSUTIL_OK:
            self.status = STATUS_ERROR
            self.status_detail = "psutil not installed"
        else:
            self.status = STATUS_OK

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        if self.status != STATUS_OK:
            self.emit_gap(f"network sensor unavailable: {self.status_detail}")
            return
        # Warm snapshot so startup doesn't emit the whole socket table.
        self._prev = self._snapshot()
        while not self.stopping:
            self.sleep(self.interval)
            if self.stopping:
                break
            self._sweep()

    def _sweep(self) -> None:
        current = self._snapshot()
        known = self._prev

        for key, conn in current.items():
            laddr, lport, raddr, rport, proto = key
            status = conn.get("status")
            if key not in known:
                if status == "LISTEN":
                    self._emit_conn(conn, "net.listen", "inbound")
                elif status in ("ESTABLISHED", "SYN_SENT"):
                    direction = "outbound" if raddr else "inbound"
                    self._emit_conn(conn, "net.connection", direction)
                if raddr:
                    self.enricher.submit(raddr)
            elif status == "ESTABLISHED" and known[key].get("status") != "ESTABLISHED":
                self._emit_conn(conn, "net.connection", "outbound" if raddr else "inbound")

        # Attach enrichment for endpoints that became ready.
        ready = {}
        for ip in list(self._pending_enrich):
            enr = self.enricher.poll(ip)
            if enr is not None:
                ready[ip] = enr
                self._pending_enrich.discard(ip)
                self._emit_enrichment(ip, enr)
        self._prev = current

    def _snapshot(self) -> Dict[Tuple, Dict[str, Any]]:
        out: Dict[Tuple, Dict[str, Any]] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.denied_ownership += 1
            return out
        for c in conns:
            try:
                laddr = c.laddr.ip if c.laddr else None
                lport = c.laddr.port if c.laddr else None
                raddr = c.raddr.ip if c.raddr else None
                rport = c.raddr.port if c.raddr else None
            except Exception:
                continue
            if not laddr and not raddr:
                continue
            owner_pid = None
            owner = None
            ownership = "unknown"
            if c.pid:
                owner_pid = c.pid
                ownership = "observed"
                try:
                    owner = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            excluded = owner in (self.settings.networks.excluded_processes or [])
            if excluded:
                continue
            out[(laddr, lport, raddr, rport, proto)] = {
                "_laddr": laddr,
                "_lport": lport,
                "_raddr": raddr,
                "_rport": rport,
                "_proto": proto,
                "status": c.status,
                "owner_pid": owner_pid,
                "owner_process": owner,
                "ownership": ownership,
            }
        return out

    # ------------------------------------------------------------------ #

    def _emit_conn(self, conn: Dict[str, Any], event_type: str, direction: str) -> None:
        enr = None
        raddr = conn.get("_raddr")
        details: Dict[str, Any] = {}
        allowlisted = None
        if raddr:
            allowlisted = self._is_allowlisted(raddr)
            details["allowlisted"] = allowlisted
            details["direction"] = direction
        self.emit(
            {
                "event_type": event_type,
                "network": {
                    "local_addr": conn.get("_laddr"),
                    "local_port": conn.get("_lport"),
                    "remote_addr": raddr,
                    "remote_port": conn.get("_rport"),
                    "proto": conn.get("_proto", "tcp"),
                    "status": conn.get("status"),
                    "direction": direction,
                    "owner_pid": conn.get("owner_pid"),
                    "owner_process": conn.get("owner_process"),
                    "ownership": conn.get("ownership"),
                    "enrichment": None,
                },
                "details": details,
                "observation": "observed",
                "confidence": 0.7 if conn.get("owner_pid") else 0.4,
            }
        )

    def _emit_enrichment(self, ip: str, enr: NetworkEnrichment) -> None:
        self.emit(
            {
                "event_type": "net.enrich",
                "network": {"remote_addr": ip, "enrichment": enr.model_dump(mode="json")},
                "details": {"note": "enrichment is inferred context, not identity"},
                "observation": "inferred",
                "confidence": 0.4,
            }
        )

    def _is_allowlisted(self, ip: str) -> bool:
        import ipaddress as _ipa

        nets = list(self.settings.networks.trusted_networks)
        local_services = [
            (s.get("host"), s.get("port")) for s in self.settings.networks.local_services
        ]
        try:
            addr = _ipa.ip_address(ip)
        except ValueError:
            return True  # hostnames: treat unknown forms as not-suspicious here
        for cidr in nets:
            try:
                if addr in _ipa.ip_network(cidr):
                    return True
            except ValueError:
                continue
        for host, _port in local_services:
            try:
                if addr == _ipa.ip_address(host):
                    return True
            except ValueError:
                continue
        return False

    def close(self) -> None:
        self.enricher.close()

    def health(self) -> Dict[str, Any]:
        h = super().health()
        h["denied_ownership_snapshots"] = self.denied_ownership
        h["tracked_endpoints"] = len(self._prev)
        return h
