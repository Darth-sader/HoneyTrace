"""HoneyTrace CLI controller.

States are explicit: disarmed / armed / degraded / stopping (arming.json).
Containment additionally requires `arm --mode contain --confirm`.

Commands:
    run            start the daemon in the foreground
    start/stop/restart/status   service control (systemd when available)
    arm/disarm     arming switch
    doctor         dependency, permission and configuration diagnostics
    test-config    validate all configuration files
    test           self-test: synthetic event through the full pipeline
    verify         verify journal chain, manifest and optionally a bundle
    report         render HTML reports (timeline + profile) to data/reports
    export         build a verifiable case bundle
    replay         evaluate stored/synthetic events against the rules
    decoys         generate | list | check | clean decoys
    serve          run the local dashboard
    demo           one-click isolated demo scenario
    emergency-off  stop responses, roll back HoneyTrace's own changes
    clean          remove ONLY HoneyTrace-owned runtime artifacts
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from honeytrace import __version__
from honeytrace.config import ConfigError, find_project_root, load_settings

op_log = logging.getLogger("honeytrace.cli")


def _setup_logging(settings, verbose: bool) -> Path:
    level = logging.DEBUG if verbose else getattr(logging, settings.honeytrace.logging.level, logging.INFO)
    logs_dir = settings.logs_dir
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / "honeytrace.log"
    try:
        from logging.handlers import RotatingFileHandler

        handler: logging.Handler = RotatingFileHandler(
            log_path, maxBytes=settings.honeytrace.logging.rotate_when_mb * 1024 * 1024,
            backupCount=settings.honeytrace.logging.keep_files, encoding="utf-8",
        )
    except OSError:
        handler = logging.NullHandler()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=[handler, logging.StreamHandler(sys.stderr)],
    )
    # Keep operational logs separate from evidence by construction: the
    # journal writer never receives log records and vice versa.
    return log_path


def _daemon(args) -> "HoneytraceDaemon":
    from honeytrace.daemon import HoneytraceDaemon

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    _setup_logging(settings, args.verbose)
    return HoneytraceDaemon(settings)


# --------------------------------------------------------------------------- #
# Command implementations
# --------------------------------------------------------------------------- #

def cmd_run(args) -> int:
    daemon = _daemon(args)
    daemon.run_forever()
    return 0


def cmd_start(args) -> int:
    if _systemctl_available():
        return _systemctl(["start", "honeytrace.service"])
    proc = subprocess.Popen(
        [sys.executable, "-m", "honeytrace", "run"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, cwd=os.getcwd(),
    )
    print(f"honeytrace daemon started in background (pid {proc.pid})")
    return 0


def cmd_stop(args) -> int:
    if _systemctl_available():
        return _systemctl(["stop", "honeytrace.service"])
    settings = load_settings(Path(args.project_root) if args.project_root else None)
    pid_file = settings.data_dir / "state" / "honeytrace.pid"
    if not pid_file.exists():
        print("not running (no pid file)")
        return 0
    try:
        pid = int(pid_file.read_text().strip())
    except ValueError:
        return 1
    try:
        if os.name == "posix":
            os.kill(pid, 15)
        else:
            subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True)
        print(f"sent stop signal to pid {pid}")
    except OSError as exc:
        print(f"failed to signal pid {pid}: {exc}")
        return 1
    return 0


def cmd_restart(args) -> int:
    cmd_stop(args)
    import time

    time.sleep(1.0)
    return cmd_start(args)


def cmd_status(args) -> int:
    settings = load_settings(Path(args.project_root) if args.project_root else None)
    health_path = settings.data_dir / "health.json"
    print(f"HoneyTrace {__version__} | root: {settings.root}")
    if not health_path.exists():
        print("daemon: not running (no health report found)")
        return 0
    try:
        report = json.loads(health_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        print("daemon: health report unreadable")
        return 1
    print(f"reported at : {report.get('timestamp_utc')}")
    for c in report.get("collectors", []):
        print(
            f"  {c['collector']:<10} {c['status']:<12} events={c.get('events_emitted', 0):<8} "
            f"errors={c.get('errors', 0)} last={c.get('last_event_utc') or '-'}"
            + (f"  [{c.get('detail')}]" if c.get("detail") else "")
        )
    j = report.get("journal", {})
    print(f"journal     : seq={j.get('sequence')} written={j.get('total_written')} "
          f"dropped={j.get('dropped_events')} queue={j.get('queue_depth')}")
    inc = report.get("incidents", {})
    print(f"incidents   : unread={inc.get('unread')} active={inc.get('active')}")
    disk = report.get("disk", {})
    if disk.get("percent") is not None:
        print(f"disk        : {disk.get('used_mb')} MB used, {disk.get('free_mb')} MB free ({disk.get('percent')}%)")
    for alert in report.get("alerts", [])[-5:]:
        print(f"ALERT       : {alert.get('message')}")
    return 0


def cmd_arm(args) -> int:
    settings = load_settings(Path(args.project_root) if args.project_root else None)
    _setup_logging(settings, args.verbose)
    from honeytrace.engine.response import ArmingState

    ok, problems = _full_validation(settings)
    if not ok:
        print("cannot arm - configuration problems:")
        for p in problems:
            print(f"  - {p}")
        return 1

    if args.mode == "contain" and not args.confirm:
        print("contain mode requires explicit confirmation: arm --mode contain --confirm")
        return 1
    extra = settings.check_mode_transition(args.mode)
    if extra and not args.confirm:
        print("containment preconditions not met:")
        for p in extra:
            print(f"  - {p}")
        return 1
    if extra:
        print("warning: arming contain with preconditions flagged:")
        for p in extra:
            print(f"  - {p}")

    arming = ArmingState(settings.data_dir / "state")
    arming.arm(args.mode, confirm_containment=bool(args.confirm and args.mode == "contain"))
    print(f"armed: mode={args.mode} containment={'ENABLED' if arming.containment_armed else 'disabled'}")
    if not arming.containment_armed:
        print("containment actions will be recorded as proposals only.")
    return 0


def cmd_disarm(args) -> int:
    settings = load_settings(Path(args.project_root) if args.project_root else None)
    from honeytrace.engine.response import ArmingState

    arming = ArmingState(settings.data_dir / "state")
    arming.disarm()
    print("disarmed; containment actions will never be applied")
    return 0


def cmd_emergency_off(args) -> int:
    settings = load_settings(Path(args.project_root) if args.project_root else None)
    _setup_logging(settings, args.verbose)
    from honeytrace.engine.response import ArmingState, ResponseEngine

    arming = ArmingState(settings.data_dir / "state")
    engine = ResponseEngine(settings, arming)
    summary = engine.emergency_off()
    print(json.dumps(summary, indent=2))
    print("emergency off complete: responses disabled, containment rolled back (idempotent).")
    return 0


def cmd_doctor(args) -> int:
    settings = load_settings(Path(args.project_root) if args.project_root else None, strict=False)
    print(f"HoneyTrace doctor | project root: {settings.root}")
    failures = 0

    ok, problems = _full_validation(settings)
    print(f"[{'OK' if ok else 'FAIL'}] configuration")
    for p in problems:
        print(f"     - {p}")
    failures += 0 if ok else 1

    checks = _dependency_checks(settings)
    for name, (ok, detail) in checks.items():
        print(f"[{'OK' if ok else 'WARN' if ok is None else 'FAIL'}] {name}: {detail}")
        if ok is False:
            failures += 1

    for path in settings.monitored_paths():
        exists = path.is_dir()
        print(f"[{'OK' if exists else 'WARN'}] monitored path {path}" + ("" if exists else " (missing)"))

    journal_dir = settings.data_dir / "events"
    if journal_dir.exists():
        from honeytrace.evidence.verification import verify_journal

        report = verify_journal(journal_dir, key_path=settings.data_dir / "state" / "checkpoint.key")
        print(f"[{'OK' if report['ok'] else 'FAIL'}] evidence journal: "
              f"{report['records']} records, breaks={len(report['breaks'])}, gaps={len(report['gaps'])}")
        failures += 0 if report["ok"] else 1
    else:
        print("[WARN] no evidence journal yet (daemon never ran)")

    print("doctor finished with", failures, "hard failure(s)")
    return 0 if failures == 0 else 2


def cmd_test_config(args) -> int:
    settings = load_settings(Path(args.project_root) if args.project_root else None, strict=False)
    ok, problems = _full_validation(settings)
    for p in problems:
        print(f"PROBLEM: {p}")
    print("test-config:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def cmd_test(args) -> int:
    """Self-test: one synthetic event flows through the entire pipeline."""
    from honeytrace.models.events import Event
    from honeytrace.engine.normalize import Normalizer
    from honeytrace.engine.rules import RuleEngine
    from honeytrace.engine.correlate import SessionTracker
    from honeytrace.engine.incidents import IncidentManager
    import tempfile

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    tmp = Path(tempfile.mkdtemp(prefix="honeytrace-selftest-"))
    try:
        normalizer = Normalizer()
        rules = RuleEngine(settings.rules)
        incidents = IncidentManager(tmp / "incidents")
        raw = {
            "event_type": "decoy.token_callback",
            "source": "canary",
            "actor": {"username": "labuser", "uid": 1001, "source_ip": "203.0.113.7", "attribution": "observed"},
            "session_id": "selftest-1",
            "decoy_id": "DCY-SELFTEST",
            "details": {"token": "selftest", "note": "synthetic"},
            "observation": "observed",
            "confidence": 0.9,
        }
        event = normalizer.normalize(raw)
        assert event is not None, "normalizer dropped the synthetic event"
        matches = rules.on_event(event)
        rule_ids = [m.rule_id for m in matches]
        assert "R-CANARY-010" in rule_ids and "R-DECOY-001" in rule_ids, f"rules did not fire: {rule_ids}"
        touched = incidents.on_matches(matches, event=event, sensor_status={"canary": "ok"})
        assert touched, "incident manager created no incident"
        inc = touched[0]
        print("self-test OK:")
        print(f"  event       {event.event_id} ({event.event_type})")
        print(f"  rules fired {rule_ids}")
        print(f"  incident    {inc.incident_id} severity={inc.severity} confidence={inc.confidence}")
        return 0
    finally:
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)


def cmd_verify(args) -> int:
    settings = load_settings(Path(args.project_root) if args.project_root else None)
    if getattr(args, "bundle", None):
        from honeytrace.evidence.export import verify_bundle

        report = verify_bundle(Path(args.bundle))
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1

    from honeytrace.evidence.verification import coverage_summary, verify_event_ids_unique, verify_journal
    from honeytrace.evidence.manifest import ArtifactManifest

    events_dir = settings.data_dir / "events"
    chain = verify_journal(events_dir, key_path=settings.data_dir / "state" / "checkpoint.key")
    dupes = verify_event_ids_unique(events_dir)
    manifest = ArtifactManifest(settings.data_dir / "manifests")
    artifacts = manifest.verify_all()
    coverage = coverage_summary(events_dir)
    print(json.dumps(
        {"chain": chain, "duplicate_event_ids": dupes, "artifacts": artifacts, "coverage": coverage},
        indent=2, default=str,
    ))
    ok = chain["ok"] and dupes["count"] == 0 and artifacts["mismatched"] == 0 and artifacts["missing"] == 0
    print("verify:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def cmd_report(args) -> int:
    from honeytrace.reports.dashboard import ReportRenderer

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    _setup_logging(settings, args.verbose)
    renderer = ReportRenderer(settings)
    ids = [args.incident] if args.incident else None
    paths = renderer.render_all(incident_ids=ids)
    for p in paths:
        print(f"report: {p}")
    return 0


def cmd_export(args) -> int:
    from honeytrace.evidence.export import CaseExporter
    from honeytrace.evidence.manifest import ArtifactManifest

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    exporter = CaseExporter(
        settings,
        ArtifactManifest(settings.data_dir / "manifests"),
        settings.data_dir / "incidents",
    )
    out = Path(args.out) if args.out else settings.data_dir / "reports" / f"case-{args.incident or 'all'}.zip"
    index = exporter.export(out, incident_ids=[args.incident] if args.incident else None)
    print(f"case bundle: {out}")
    print(f"  events    : {index['event_count']}")
    print(f"  incidents : {index['incident_count']}")
    print(f"  artifacts : {len(index['artifacts'])}")
    print(f"  chain ok  : {index['chain_report']['ok']}")
    return 0 if index["chain_report"]["ok"] else 1


def cmd_replay(args) -> int:
    from honeytrace.engine.normalize import Normalizer, _norm_ts
    from honeytrace.engine.rules import RuleEngine
    from honeytrace.models.events import Event

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    rules = [r for r in settings.rules if not args.rules_file]
    engine = RuleEngine(rules or settings.rules)
    normalizer = Normalizer()
    events: List[Event] = []
    with open(args.file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "event" in raw and "seq" in raw:  # journal record envelope
                raw = raw["event"]
            ev = normalizer.normalize(raw)
            if ev is None:
                continue
            events.append(ev)
    matches = engine.replay(events)
    print(f"replayed {len(events)} events -> {len(matches)} rule match(es)")
    for m in matches:
        print(f"  {m.rule_id} [{m.severity}] conf={m.confidence} events={len(m.contributing_event_ids)}")
        print(f"    {m.explanation}")
    return 0


def cmd_decoys(args) -> int:
    from honeytrace.deception.inventory import DecoyInventory
    from honeytrace.deception.tokens import TokenRegistry
    from honeytrace.deception.workspace import DeceptionWorkspace

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    _setup_logging(settings, args.verbose)
    inventory = DecoyInventory(settings.data_dir)
    registry = TokenRegistry(
        callback_url_base=f"http://{settings.honeytrace.network.canary_host}:{settings.honeytrace.network.canary_port}/beacon"
    )
    workspace = DeceptionWorkspace(settings, inventory, registry)
    workspace.set_boundaries(settings.decoys_dir, settings.monitored_paths())

    if args.action == "generate":
        report = workspace.deploy_from_honeylist()
        print(f"placed {len(report['placed'])} decoy(s)")
        for d in report["placed"]:
            print(f"  {d['decoy_id']}  {d['path']}")
        for f in report["failed"]:
            print(f"  FAILED: {f}")
        return 0 if not report["failed"] else 1
    if args.action == "list":
        for d in inventory.all():
            print(f"{d['decoy_id']}  {d['type']:<5} integrity={d.get('integrity')}  {d['path']}")
        print(f"{len(inventory.all())} decoy(s) in inventory")
        return 0
    if args.action == "check":
        changed = workspace.verify_integrity()
        if changed:
            for d in changed:
                print(f"INTEGRITY {d['integrity']}: {d['path']}")
        else:
            print("all decoys intact")
        return 0
    if args.action == "clean":
        report = workspace.cleanup(force=args.force)
        print(f"removed {len(report['removed'])}, preserved {len(report['preserved'])}, missing {report['missing']}")
        for p in report["preserved"]:
            print(f"  preserved: {p['path']} ({p['reason']})")
        return 0
    return 1


def cmd_serve(args) -> int:
    from honeytrace.reports.dashboard import DashboardServer

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    server = DashboardServer(settings, port=args.port, host=args.host)
    server.serve()
    return 0


def cmd_demo(args) -> int:
    """One-click demo: isolated scenario, controlled 'attack', reports."""
    import tempfile
    import time as _time

    from honeytrace.engine.incidents import IncidentManager
    from honeytrace.engine.normalize import Normalizer
    from honeytrace.engine.rules import RuleEngine
    from honeytrace.reports.dashboard import ReportRenderer

    settings = load_settings(Path(args.project_root) if args.project_root else None)
    _setup_logging(settings, args.verbose)
    print("HoneyTrace demo - fully offline, synthetic data only")

    # 1. Deploy decoys into the lab tree.
    from honeytrace.deception.inventory import DecoyInventory
    from honeytrace.deception.tokens import TokenRegistry
    from honeytrace.deception.workspace import DeceptionWorkspace

    inventory = DecoyInventory(settings.data_dir)
    registry = TokenRegistry()
    workspace = DeceptionWorkspace(settings, inventory, registry)
    workspace.set_boundaries(settings.decoys_dir, settings.monitored_paths())
    report = workspace.deploy_from_honeylist()
    print(f"  decoys placed: {len(report['placed'])}")

    # 2. Replay the bundled controlled-attack trace through the engine.
    scenario = Path(__file__).resolve().parents[2] / "tests" / "scenarios" / "attack_decoy_read.jsonl"
    if not scenario.exists():
        print(f"  scenario trace missing: {scenario}")
        return 1
    normalizer = Normalizer()
    rules = RuleEngine(settings.rules)
    incidents = IncidentManager(settings.data_dir / "incidents")
    matches_total = 0
    with scenario.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            event = normalizer.normalize(raw)
            if not event:
                continue
            matches = rules.on_event(event)
            matches_total += len(matches)
            if matches:
                incidents.on_matches(matches, event=event, sensor_status={"demo": "ok"})
    print(f"  attack trace produced {matches_total} rule match(es)")

    renderer = ReportRenderer(settings)
    paths = renderer.render_all()
    for p in paths:
        print(f"  report: {p}")
    print("demo complete. Review incidents with: honeytrace status")
    return 0


def cmd_clean(args) -> int:
    """Safe uninstall: remove ONLY HoneyTrace-generated runtime artifacts."""
    settings = load_settings(Path(args.project_root) if args.project_root else None)
    data = settings.data_dir
    owned = [
        data / "events", data / "incidents", data / "manifests",
        data / "baselines", data / "reports", data / "pcap",
        data / "sessions", data / "decoys", data / "logs",
        data / "state" / "honeytrace.pid",
    ]
    if not data.exists():
        print("nothing to clean")
        return 0
    print("Removing ONLY HoneyTrace-owned runtime directories/files:")
    for path in owned:
        if path == data:
            continue
        if path.exists():
            print(f"  - {path}")
            if args.yes:
                _rm(path)
    if not args.yes:
        print("dry run: re-run with --yes to delete")
        return 0
    # Remove data/ itself only when empty.
    try:
        data.rmdir()
    except OSError:
        pass
    print("clean complete (operator config and evidence exports outside data/ are untouched)")
    return 0


def _rm(path: Path) -> None:
    import shutil

    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    else:
        try:
            path.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _full_validation(settings) -> tuple:
    from honeytrace.config import summarize_problems

    try:
        return summarize_problems(settings)
    except ConfigError as exc:
        return False, [str(exc)]


def _dependency_checks(settings) -> Dict[str, tuple]:
    checks: Dict[str, tuple] = {}
    for mod in ("yaml", "pydantic", "psutil", "jinja2"):
        try:
            __import__(mod)
            checks[mod] = (True, "installed")
        except ImportError:
            checks[mod] = (False, f"missing - pip install {mod}")
    try:
        import shutil as _sh

        for tool in ("auditctl", "ausearch"):
            checks[tool] = ((_sh.which(tool) is not None), "found" if _sh.which(tool) else "not found (file attribution degraded)")
        checks["tcpdump"] = ((_sh.which("tcpdump") is not None), "found" if _sh.which("tcpdump") else "not found (pcap disabled)")
        checks["tlog"] = ((_sh.which("tlog-rec-session") is not None), "found" if _sh.which("tlog-rec-session") else "not found (scoped recording unavailable)")
        checks["systemctl"] = ((_sh.which("systemctl") is not None), "found" if _sh.which("systemctl") else "not found")
    except Exception as exc:  # pragma: no cover
        checks["tools"] = (None, f"check error: {exc}")
    if os.name != "posix":
        checks["platform"] = (None, "not Linux - sensors will be unavailable (dev mode)")
    else:
        checks["platform"] = (True, f"Linux ({os.uname().release})")
    if os.geteuid() != 0 if hasattr(os, "geteuid") else False:
        checks["privileges"] = (None, "unprivileged mode: audit/pcap/sudo telemetry limited (dev mode OK)")
    else:
        checks["privileges"] = (True, "running privileged")
    return checks


def _systemctl_available() -> bool:
    import shutil as _sh

    return _sh.which("systemctl") is not None and Path("/etc/systemd/system/honeytrace.service").exists()


def _systemctl(cmd_args: List[str]) -> int:
    try:
        proc = subprocess.run(["systemctl", *cmd_args], check=False)
        return proc.returncode
    except OSError as exc:
        print(f"systemctl failed: {exc}")
        return 1


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeytrace",
        description="HoneyTrace - Linux intrusion deception, detection and evidence framework",
    )
    parser.add_argument("--version", action="version", version=f"honeytrace {__version__}")
    parser.add_argument("--project-root", help="override project root (defaults to nearest config/)")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, help_: str, func) -> None:
        p = sub.add_parser(name, help=help_)
        p.set_defaults(func=func)
        return p

    add("run", "run the daemon in the foreground", cmd_run)
    add("start", "start the daemon (systemd if installed)", cmd_start)
    add("stop", "stop the daemon", cmd_stop)
    add("restart", "restart the daemon", cmd_restart)
    add("status", "show daemon status from the last health report", cmd_status)

    p = add("arm", "arm HoneyTrace in a mode", cmd_arm)
    p.add_argument("--mode", choices=["observe", "deceive", "contain"], default="observe")
    p.add_argument("--confirm", action="store_true", help="required for contain mode")

    add("disarm", "disarm; response proposals only", cmd_disarm)
    add("emergency-off", "stop responses and roll back HoneyTrace's own changes", cmd_emergency_off)
    add("doctor", "diagnose dependencies, permissions and evidence integrity", cmd_doctor)
    add("test-config", "validate all configuration files", cmd_test_config)
    add("test", "run the built-in pipeline self-test", cmd_test)
    add("verify", "verify evidence chain, manifest and artifacts", cmd_verify)
    p = add("verify-bundle", "verify an exported case bundle", cmd_verify)
    p.add_argument("--bundle", required=True)

    p = add("report", "render HTML reports to data/reports", cmd_report)
    p.add_argument("--incident", help="limit to one incident id")

    p = add("export", "export a verifiable case bundle (zip)", cmd_export)
    p.add_argument("--incident", help="limit to one incident id")
    p.add_argument("--out", help="output zip path")

    p = add("replay", "evaluate events from a JSONL file against the rules", cmd_replay)
    p.add_argument("file")
    p.add_argument("--rules-file", help="alternative rules.yml")

    p = add("decoys", "generate|list|check|clean decoys", cmd_decoys)
    p.add_argument("action", choices=["generate", "list", "check", "clean"])
    p.add_argument("--force", action="store_true", help="remove modified decoys too")

    p = add("serve", "run the local HTML dashboard", cmd_serve)
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--host", default="127.0.0.1")

    add("demo", "run the offline one-click demo scenario", cmd_demo)
    p = add("clean", "remove ONLY HoneyTrace-owned runtime artifacts", cmd_clean)
    p.add_argument("--yes", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
