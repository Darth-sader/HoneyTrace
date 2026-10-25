"""Canary beacon collector: loopback HTTP listener for decoy tokens.

Behavior:
* Binds to the configured host (loopback by default; a non-loopback bind
  prints a prominent warning and requires deliberate configuration).
* Responds 200 with a 1x1 GIF to ANY request so previewers don't leak token
  validity by status code; resolution happens server-side.
* Rate-limits per token, keeps a bounded request log, and never crashes on
  malformed input.
* Emits decoy.token_callback events carrying the token, decoy id, remote
  endpoint, method, User-Agent and Referer. A callback proves decoy
  interaction - NOT who the person is (a document previewer can fetch it).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from honeytrace.collectors import STATUS_DISABLED, STATUS_ERROR, STATUS_OK, CollectorBase
from honeytrace.deception.tokens import TokenRegistry

GIF_1PX = bytes.fromhex(
    "474946383961010001008000000000000021f90401000000002c00000000010001000002024401003b"
)


class CanaryCollector(CollectorBase):
    name = "canary"

    def __init__(self, emit, settings, registry: Optional[TokenRegistry] = None):
        super().__init__(emit, settings)
        self.settings = settings
        cfg = settings.honeytrace.network
        self.host = cfg.canary_host
        self.port = cfg.canary_port
        self.registry = registry or TokenRegistry(
            callback_url_base=f"http://{self.host}:{self.port}/beacon"
        )
        self.server: Optional[ThreadingHTTPServer] = None
        self.requests_seen: List[Dict[str, Any]] = []
        self._rate: Dict[str, float] = {}
        self.rate_limit_seconds = 1.0
        self.max_log = 1000

        if not cfg.canary_enabled:
            self.status = STATUS_DISABLED
            self.status_detail = "canary disabled in configuration"
        else:
            self.status = STATUS_OK

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        if self.status != STATUS_OK:
            self.emit_gap(f"canary unavailable: {self.status_detail}")
            return
        try:
            self.server = ThreadingHTTPServer((self.host, self.port), self._handler_class())
            self.server.daemon_threads = True
        except OSError as exc:
            self.status = STATUS_ERROR
            self.status_detail = f"cannot bind {self.host}:{self.port}: {exc}"
            self.emit_gap(self.status_detail)
            return

        self.emit(
            {
                "event_type": "canary.listening",
                "details": {"host": self.host, "port": self.port},
                "observation": "observed",
                "confidence": 1.0,
            }
        )
        try:
            self.server.serve_forever(poll_interval=0.5)
        finally:
            self.server.server_close()

    def stop(self, timeout: float = 5.0) -> None:
        super().stop(timeout=timeout)
        if self.server:
            try:
                self.server.shutdown()
            except Exception:
                pass

    # ------------------------------------------------------------------ #

    def _handler_class(self):
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def _safe(self) -> None:
                try:
                    collector.handle_request(self)
                except Exception:
                    try:
                        self.send_response(400)
                        self.end_headers()
                    except Exception:
                        pass

            def do_GET(self) -> None:  # noqa: N802 (http.server API)
                self._safe()

            def do_POST(self) -> None:  # noqa: N802
                self._safe()

            def do_HEAD(self) -> None:  # noqa: N802
                self._safe()

            def log_message(self, fmt: str, *args: Any) -> None:
                pass  # keep noisy default logging out of HoneyTrace's op log

        return Handler

    def handle_request(self, handler: BaseHTTPRequestHandler) -> None:
        import time as _time

        parsed = urlparse(handler.path)
        token = None
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "beacon":
            token = parts[1]
        if token is None:
            token = (parse_qs(parsed.query).get("t") or [None])[0]

        remote = handler.client_address[0] if handler.client_address else None
        ua = handler.headers.get("User-Agent")
        referer = handler.headers.get("Referer")

        resolved = self.registry.resolve(token) if token else None
        valid = bool(resolved) and not (resolved or {}).get("expired")

        # Rate limit duplicates per token (10s window), log bounded.
        now = _time.monotonic()
        if token and valid and now - self._rate.get(token, 0.0) < self.rate_limit_seconds * 10:
            duplicate = True
        else:
            duplicate = False
            if token:
                self._rate[token] = now

        record = {
            "time": _time.time(),
            "remote": remote,
            "method": handler.command,
            "path": parsed.path,
            "token_valid": valid,
            "duplicate": duplicate,
            "user_agent": ua,
            "referer": referer,
        }
        self.requests_seen.append(record)
        if len(self.requests_seen) > self.max_log:
            self.requests_seen = self.requests_seen[-self.max_log:]

        try:
            handler.send_response(200)
            handler.send_header("Content-Type", "image/gif")
            handler.send_header("Content-Length", str(len(GIF_1PX)))
            handler.send_header("Cache-Control", "no-store")
            handler.end_headers()
            if handler.command != "HEAD":
                handler.wfile.write(GIF_1PX)
        except Exception:
            pass

        if valid and not duplicate:
            self.emit(
                {
                    "event_type": "decoy.token_callback",
                    "decoy_id": (resolved or {}).get("decoy_id"),
                    "network": {"remote_addr": remote, "direction": "inbound",
                                "local_addr": self.host, "local_port": self.port},
                    "details": {
                        "token": token,
                        "method": handler.command,
                        "user_agent": ua,
                        "referer": referer,
                        "note": "callback proves decoy interaction; attribution requires process correlation",
                    },
                    "observation": "observed",
                    "confidence": 0.95,
                }
            )

    def health(self) -> Dict[str, Any]:
        h = super().health()
        h.update({"bind": f"{self.host}:{self.port}", "tokens_issued": len(self.registry.all_tokens())})
        return h
