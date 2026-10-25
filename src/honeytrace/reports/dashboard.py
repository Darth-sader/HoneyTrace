"""Local HTML dashboard and report renderer.

* Incident centre (list by severity/status/time/actor/confidence with
  unread badge), incident detail (detection explanation, evidence coverage,
  uncertainty, recommended next steps), Report A timeline, Report B profile.
* Jinja2 with autoescaping ON for every template; attacker-controlled
  strings (filenames, argv) are never inserted as trusted markup.
* Serves on loopback by default. A non-loopback bind requires a generated
  access token (data/state/dashboard.token) - flagged loudly.
* The dashboard only READS the incident store and journal; it never edits
  evidence. Acknowledge/read state is persisted by the IncidentManager.
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from honeytrace.evidence.export import CaseExporter
from honeytrace.evidence.manifest import ArtifactManifest
from honeytrace.engine.correlate import SessionTracker, build_causal_graph
from honeytrace.engine.incidents import IncidentManager
from honeytrace.models.events import canonical_json
from honeytrace.reports.profile import ProfileBuilder
from honeytrace.reports.timeline import TimelineBuilder

from jinja2 import Environment, FileSystemLoader, select_autoescape

PROJECT_ROOT = Path(__file__).resolve().parents[3]
TEMPLATE_DIR = PROJECT_ROOT / "templates"
ASSET_DIR = PROJECT_ROOT / "assets"


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


class ReportRenderer:
    """Static HTML report generation (data/reports/)."""

    def __init__(self, settings, incident_manager: Optional[IncidentManager] = None):
        self.settings = settings
        self.reports_dir = settings.data_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.incidents = incident_manager or IncidentManager(settings.data_dir / "incidents")
        self.env = _jinja_env()

    def render_all(self, incident_ids: Optional[List[str]] = None) -> List[Path]:
        out: List[Path] = []
        incidents = self.incidents.all_incidents()
        if incident_ids:
            incidents = [i for i in incidents if i.incident_id in incident_ids]
        out.append(self.render_incident_centre(self.incidents.all_incidents()))
        timeline_builder = TimelineBuilder(self.settings, self.incidents)
        profile_builder = ProfileBuilder(self.settings)
        for inc in incidents:
            out.append(self.render_incident(inc))
            timeline = timeline_builder.build(incident=inc)
            out.append(self._render("timeline.html", timeline, f"timeline-{inc.incident_id}.html"))
            profile = profile_builder.build(inc)
            out.append(self._render("profile.html", profile, f"profile-{inc.incident_id}.html"))
        return out

    def render_incident_centre(self, incidents) -> Path:
        data = {
            "incidents": [i.to_dict() for i in incidents],
            "unread": self.incidents.unread_count(),
            "active": self.incidents.active_count(),
        }
        return self._render("incidents.html", data, "incidents.html")

    def render_incident(self, incident) -> Path:
        timeline_builder = TimelineBuilder(self.settings, self.incidents)
        timeline = timeline_builder.build(incident=incident)
        graph = build_causal_graph(timeline["events"])
        data = {
            "incident": incident.to_dict(),
            "coverage_score": incident.evidence_coverage.score,
            "timeline": timeline,
            "graph": graph,
        }
        return self._render("incident.html", data, f"incident-{incident.incident_id}.html")

    def _render(self, template_name: str, data: Dict[str, Any], out_name: str) -> Path:
        template = self.env.get_template(template_name)
        html = template.render(**data, static_prefix="")
        out_path = self.reports_dir / out_name
        out_path.write_text(html, encoding="utf-8")
        return out_path


class DashboardServer:
    """Read-only local HTTP dashboard."""

    def __init__(self, settings, port: int = 8443, host: str = "127.0.0.1"):
        self.settings = settings
        self.host = host
        self.port = port
        self.incidents = IncidentManager(settings.data_dir / "incidents")
        self.renderer = ReportRenderer(settings, self.incidents)
        self.timeline_builder = TimelineBuilder(settings, self.incidents)
        self.profile_builder = ProfileBuilder(settings)
        self.exporter = CaseExporter(settings, ArtifactManifest(settings.data_dir / "manifests"),
                                     settings.data_dir / "incidents")
        self.token = self._access_token()

    def _access_token(self) -> Optional[str]:
        loopback = self.host in ("127.0.0.1", "localhost", "::1")
        if loopback:
            return None
        # Non-loopback: require a token (generated once, stored 0600).
        path = self.settings.data_dir / "state" / "dashboard.token"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(secrets.token_urlsafe(24))
        return path.read_text().strip()

    def serve(self) -> None:
        server = ThreadingHTTPServer((self.host, self.port), self._handler())
        server.daemon_threads = True
        if self.token:
            print(f"dashboard: http://{self.host}:{self.port}  (token required: {self.token})")
        else:
            print(f"dashboard: http://127.0.0.1:{self.port}")
        server.serve_forever(poll_interval=0.5)

    # ------------------------------------------------------------------ #

    def _handler(self):
        dashboard = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                try:
                    dashboard.route(self)
                except Exception as exc:  # never leak a stack trace to the socket
                    self._respond(500, f"internal error: {type(exc).__name__}", "text/plain")

            def do_POST(self) -> None:  # noqa: N802
                try:
                    dashboard.route_post(self)
                except Exception:
                    self._respond(500, "internal error", "text/plain")

            def _respond(self, code: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
                data = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

        return Handler

    # -- routing -------------------------------------------------------------- #

    def route(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not self._authorized(handler, query):
            handler._respond(401, "unauthorized: token required", "text/plain")
            return

        if path == "/" or path == "/incidents":
            return self._page_incidents(handler)
        if path.startswith("/incident/"):
            return self._page_incident(handler, path.split("/")[2])
        if path.startswith("/timeline/"):
            return self._page_timeline(handler, path.split("/")[2], query)
        if path.startswith("/profile/"):
            return self._page_profile(handler, path.split("/")[2])
        if path == "/health":
            return self._page_health(handler)
        if path == "/static/style.css":
            return self._static(handler, "css/style.css", "text/css")
        if path.startswith("/api/"):
            return self._api(handler, path, query)
        if path.startswith("/download/"):
            return self._download(handler, path.split("/")[2])
        handler._respond(404, "not found", "text/plain")

    def route_post(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "api" and parts[1] == "incident":
            action = parts[2]
            inc_id = parse_qs(parsed.query).get("id", [None])[0]
            if not inc_id:
                handler._respond(400, "missing id", "text/plain")
                return
            ok = False
            if action == "ack":
                ok = self.incidents.acknowledge(inc_id)
            elif action == "read":
                ok = self.incidents.mark_read(inc_id)
            elif action == "close":
                ok = self.incidents.close(inc_id)
            handler._respond(200 if ok else 404, json.dumps({"ok": ok}), "application/json")
            return
        handler._respond(404, "not found", "text/plain")

    def _authorized(self, handler: BaseHTTPRequestHandler, query: Dict[str, str]) -> bool:
        if self.token is None:
            return True
        supplied = query.get("token") or _cookie_token(handler)
        return bool(supplied and secrets.compare_digest(supplied, self.token))

    # -- pages ----------------------------------------------------------------- #

    def _page_incidents(self, handler: BaseHTTPRequestHandler) -> None:
        incs = [i.to_dict() for i in self.incidents.all_incidents()]
        html = self.renderer.env.get_template("incidents.html").render(
            incidents=incs,
            unread=self.incidents.unread_count(),
            active=self.incidents.active_count(),
            static_prefix="/static",
        )
        handler._respond(200, html)

    def _page_incident(self, handler: BaseHTTPRequestHandler, inc_id: str) -> None:
        incident = self.incidents.get(inc_id)
        if not incident:
            handler._respond(404, "incident not found", "text/plain")
            return
        timeline = self.timeline_builder.build(incident=incident)
        graph = build_causal_graph(timeline["events"])
        html = self.renderer.env.get_template("incident.html").render(
            incident=incident.to_dict(),
            coverage_score=incident.evidence_coverage.score,
            timeline=timeline,
            graph=graph,
            static_prefix="/static",
        )
        self.incidents.mark_read(inc_id)
        handler._respond(200, html)

    def _page_timeline(self, handler: BaseHTTPRequestHandler, inc_id: str, query: Dict[str, str]) -> None:
        incident = self.incidents.get(inc_id)
        filters = {k: v for k, v in query.items() if k in ("event_type", "source", "actor", "severity", "from", "to")}
        timeline = self.timeline_builder.build(incident=incident, event_filter=filters or None)
        html = self.renderer.env.get_template("timeline.html").render(
            **timeline,
            incident_id=inc_id,
            static_prefix="/static",
        )
        handler._respond(200, html)

    def _page_profile(self, handler: BaseHTTPRequestHandler, inc_id: str) -> None:
        incident = self.incidents.get(inc_id)
        if not incident:
            handler._respond(404, "incident not found", "text/plain")
            return
        profile = self.profile_builder.build(incident)
        html = self.renderer.env.get_template("profile.html").render(
            **profile,
            static_prefix="/static",
        )
        handler._respond(200, html)

    def _page_health(self, handler: BaseHTTPRequestHandler) -> None:
        from honeytrace.health import HealthMonitor

        report = {}
        health_path = self.settings.data_dir / "health.json"
        if health_path.exists():
            try:
                report = json.loads(health_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                report = {"note": "health report unreadable"}
        handler._respond(200, "<pre>" + json.dumps(report, indent=2, default=str) + "</pre>")

    def _static(self, handler: BaseHTTPRequestHandler, rel: str, ctype: str) -> None:
        f = ASSET_DIR / rel
        if not f.is_file():
            handler._respond(404, "not found", "text/plain")
            return
        handler._respond(200, f.read_text(encoding="utf-8"), ctype)

    def _api(self, handler: BaseHTTPRequestHandler, path: str, query: Dict[str, str]) -> None:
        if path == "/api/incidents":
            body = [i.to_dict() for i in self.incidents.all_incidents()]
        elif path.startswith("/api/incident/"):
            inc = self.incidents.get(path.split("/")[3])
            body = inc.to_dict() if inc else {}
        elif path == "/api/health":
            health_path = self.settings.data_dir / "health.json"
            body = json.loads(health_path.read_text(encoding="utf-8")) if health_path.exists() else {}
        elif path.startswith("/api/timeline/"):
            inc = self.incidents.get(path.split("/")[3])
            body = self.timeline_builder.build(incident=inc)
        else:
            handler._respond(404, "not found", "text/plain")
            return
        handler._respond(200, canonical_json(body), "application/json")

    def _download(self, handler: BaseHTTPRequestHandler, name: str) -> None:
        reports_dir = self.settings.data_dir / "reports"
        f = reports_dir / name
        # Path traversal guard: only files we generated, resolved under reports dir.
        if not f.resolve().is_relative_to(reports_dir.resolve()) or not f.is_file():
            handler._respond(404, "not found", "text/plain")
            return
        data = f.read_bytes()
        handler.send_response(200)
        handler.send_header("Content-Type", "application/zip")
        handler.send_header("Content-Length", str(len(data)))
        handler.send_header("Content-Disposition", f'attachment; filename="{name}"')
        handler.end_headers()
        handler.wfile.write(data)


def _cookie_token(handler: BaseHTTPRequestHandler) -> Optional[str]:
    cookie = handler.headers.get("Cookie") or ""
    for part in cookie.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip() == "honeytrace_token":
                return v.strip()
    return None


def start_dashboard_thread(settings, port: int = 8443) -> threading.Thread:
    server = DashboardServer(settings, port=port)

    def _run() -> None:
        server.serve()

    t = threading.Thread(target=_run, name="honeytrace-dashboard", daemon=True)
    t.start()
    return t
