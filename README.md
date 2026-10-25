# HoneyTrace

**HoneyTrace** is a Linux intrusion *deception, detection and evidence*
framework for isolated lab machines and disposable VMs. It plants believable
synthetic decoy files in designated lab paths, watches how sessions interact
with them, correlates filesystem / process / authentication / network
telemetry into incidents, keeps a tamper-evident JSONL evidence journal, and
renders two reports per incident — **Report A: attack timeline** and
**Report B: activity profile**.

> ⚠️ **Scope.** HoneyTrace is a lab and research tool. It is not an EDR, not
> anti-malware, and not a forensically sound recorder for production hosts.
> Run it on a dedicated lab machine or disposable VM — never on a host whose
> files or network restrictions you cannot afford to disrupt.

---

## Architecture

```
collectors (observe only)          engine                       surfaces
┌─────────────────────┐   ┌──────────────────────────┐   ┌────────────────┐
│ filesystem (inotify)│   │ normalize (schema+redact)│   │ evidence journal│
│ audit (auditd tail) │──▶│ rules (YAML, deterministic)│─▶│ (JSONL, hash   │
│ process (psutil)    │   │ correlate (sessions)      │   │  chain+HMAC ckpt)│
│ auth (journal/log)  │   │ incidents (grouping)      │   │ incident store │
│ network (sockets)   │   │ response (policy-gated)   │   │ HTML dashboard │
│ pcap (opt-in ring)  │   └──────────────────────────┘   │ notifications  │
│ canary (loopback HTTP)│                                │ case export    │
└─────────────────────┘                                  └────────────────┘
```

Communication rules:

1. **Collectors produce events.** They never block users, never write reports.
2. **The normalizer** converts collector output into one common event schema
   (and redacts credential-shaped strings before anything is stored).
3. **The correlation engine** links events into sessions and incidents.
4. **The evidence writer** records events and artifact references (the only
   writer of `events.jsonl`).
5. **The response engine** evaluates approved policies separately from
   detection — proposals in Observe mode, scoped actions only when armed.
6. **The report layer** reads the incident store and journal; it never edits
   evidence.

HoneyTrace's own diagnostics go through Python `logging` into
`data/logs/honeytrace.log`; incident evidence goes through the structured
JSONL journal. The two streams never mix.

## Repository layout

```
config/    operator configuration (yml)          templates/  Jinja2 report templates
src/honeytrace/  application code                assets/     css + icons
  models/     events, incidents, actors          decoys/     synthetic content root
  collectors/ filesystem, audit, process,        data/       runtime evidence (configurable)
              auth, network, pcap, canary,         events/ incidents/ baselines/
              session                              manifests/ pcap/ sessions/ reports/
  engine/     normalize, rules, correlate,       systemd/    service + health timer
              incidents, response                scripts/    install_lab.sh demo.sh emergency_off.sh
  deception/  generator, inventory, tokens,      tests/      unit/ integration/ fixtures/
              workspace                                      performance/ scenarios/
  evidence/   journal, hashing, manifest,
              verification, export
  reports/    timeline, profile, dashboard
```

`src/` is application code, `config/` is operator configuration, `decoys/`
is synthetic content, `data/` is runtime evidence. **Runtime evidence is
never written into the source tree** — the data directory is configurable
(`paths.data`) and resolved with `pathlib` (no hard-coded home paths).

## Install (Linux lab machine / VM)

```bash
sudo bash scripts/install_lab.sh     # accounts, packages, audit rules, systemd
source .venv/bin/activate
honeytrace doctor                    # dependency/permission diagnostics
honeytrace test-config               # validate configuration
honeytrace decoys generate           # plant synthetic decoys
sudo honeytrace arm --mode observe   # observe: detection only, no actions
sudo systemctl start honeytrace
honeytrace status
```

Unprivileged development mode works too: `make setup && make run` — sensors
that need privileges (audit, pcap) report themselves *unavailable* as
coverage gaps instead of failing.

Windows/macOS are **not** runtime targets (inotify, auditd, cgroups); the
code imports safely and the test suite runs anywhere for development.

## Operating modes and the arming switch

| Mode      | Behavior                                                                 |
|-----------|--------------------------------------------------------------------------|
| `observe` | Collect + detect. Every response is a recorded *proposal*.               |
| `deceive` | Additionally route lab sessions toward synthetic decoy resources.        |
| `contain` | Additionally allow scoped, reversible containment — requires `honeytrace arm --mode contain --confirm`. |

Arming state lives in `data/state/arming.json` (0600). It is a safety
interlock, **not** an authorization boundary — a local root can change it.
Containment additionally refuses to act on any UID other than the
configured `lab_user`, and skips identities listed in
`response.trusted_users` / `maintenance_sessions` / `networks.trusted_networks`.

### Containment, dry-run and rollback

- `response.dry_run: true` (default) predicts actions and changes nothing.
- Applied actions are scoped firewall rules tagged `honeytrace:<incident>`
  (iptables/nft) limited to the lab UID — never host-wide OUTPUT rules.
- Every applied action is journaled with its exact rollback command in
  `data/state/rollback.jsonl`.
- `honeytrace emergency-off` (or `scripts/emergency_off.sh`) first stops new
  responses, then rolls back **only** HoneyTrace-tagged changes. Idempotent;
  safe to run twice; never deletes evidence.

## The evidence blackbox

- `data/events/events.jsonl` — one normalized JSON event per line with
  `event_id`, `timestamp_utc` (event time), `observed_at_utc` (collection
  time), `event_type`, `source`, `actor`, `session_id`, `process`, `target`,
  `network`, `rule_matches`, `incident_id`, `artifacts`. Optional fields are
  *absent*, never fabricated.
- Append-only by design; a queue separates collector callbacks from disk and
  tracks queue depth plus a dropped-event counter.
- Hash chain: every record includes the previous record's hash and its own
  SHA-256 over the canonical record.
- HMAC checkpoints every N records, key stored outside the evidence dir
  (`data/state/checkpoint.key`).
- `honeytrace verify` re-walks the chain, detects tampering, gaps, corrupt
  lines and duplicate IDs; `honeytrace export` produces a verifiable zip
  case bundle (`honeytrace verify --bundle case.zip` re-verifies anywhere).

**Honest integrity limit:** a root-level attacker can rewrite the journal
*and* the checkpoints. The chain and checkpoints make silent modification
detectable on the happy path — they do not make the log invulnerable. For
stronger guarantees, export case bundles off-box.

## Detection rules

`config/rules.yml` — stable IDs, severities, MITRE references, and a small
deterministic condition DSL (`all` / `any` / `sequence`, thresholds, time
windows, per-session grouping, suppression windows). Severity (potential
impact) and confidence (evidence strength) are computed **separately**.

Every rule match carries: contributing event IDs, observed-vs-required
thresholds, a human-readable explanation, and explicitly-listed missing
evidence (e.g. "no audit exec attribution"). Replay any trace:

```bash
honeytrace replay tests/scenarios/attack_decoy_read.jsonl
```

## Reports

- **Incident centre** (`honeytrace serve` → http://127.0.0.1:8443): list by
  severity/status/actor/confidence; unread badge is distinct from active
  incidents and from active sessions. Opening an incident marks it *read*,
  never *resolved*.
- **Report A — attack timeline**: chronological file/process/session/network/
  response events with expandable evidence, process ancestry, artifact hashes
  (shown only when the file exists), filters, and an **evidence gaps**
  section (sensor downtime, dropped events, unattributed events).
- **Report B — activity profile**: pseudonymous actor, session context,
  endpoints (enrichment marked approximate), behavior summary, decoy
  interest, evidence map separating direct observations from correlations
  and enrichment, plus limitations. It answers: *what did this session do,
  what evidence supports that, what remains unknown?*
- All HTML is rendered with Jinja2 autoescaping; attacker-controlled strings
  (filenames, argv) are escaped — covered by tests.

## Sensors and honest limitations

| Sensor | Source | Needs | Blind spots |
|--------|--------|-------|-------------|
| filesystem | inotify (ctypes) | none | **no actor info** — attribution requires audit correlation; queue overflow = lost events |
| audit | auditd log tail | read access (adm / CAP_AUDIT_READ) + rules from install_lab.sh | unavailable ⇒ file attribution degrades to "unknown" |
| process | psutil scan | none | `/proc` denied fields are absent (not zero); PID reuse guarded by start time |
| auth | journalctl / auth.log | journal or rsyslog | rotation and denial handled as gaps |
| network | psutil sockets | root for other users' ownership | ownership "denied"/"ambiguous" recorded, never guessed |
| pcap | tcpdump ring (opt-in) | root/CAP_NET_ADMIN | captures are bounded rings, not complete records |
| canary | loopback HTTP | none | a callback proves decoy interaction, **not** who the person is (previewers fetch beacons too) |
| session | tlog artifacts | tlog installed + operator-configured | no raw TTY polling is performed, ever |

**Threat model / limitations (read before trusting any output):**

- A **root or kernel-level attacker** bypasses everything: they can unload
  sensors, edit the journal, re-sign checkpoints, or simply not trigger
  decoys. HoneyTrace assumes a *non-root-adversary-in-the-lab* model.
- **IP attribution is spoofable and shallow** — an IP address is not a
  person; GeoIP/ASN/RDAP are approximate enrichment, time-stamped, never
  identity.
- **Evidence completeness ≠ truth.** Coverage scores describe which sensors
  contributed, not that the reconstruction is complete.
- inotify is not a complete read-audit trail; reads are only attributed when
  auditd telemetry covers the same moment.
- Redaction is pattern-based; novel secret formats may slip through.
- Containment acts only inside the lab UID scope; it cannot stop a process
  HoneyTrace cannot see (root kits, kernel modules).

## Demo

```bash
scripts/demo.sh          # decoys + self-test + replay + reports
honeytrace serve         # browse incidents, timeline, profile
```

Evaluation corpus lives in `tests/scenarios/` (benign + attack traces with
expected rule outcomes) and replays deterministically — event-time based —
so rulesets can be compared without re-running sensors.

## Tests

```bash
make test                # unit + integration
make performance         # throughput/latency measurements (marked slow)
```

Coverage includes: normalization/redaction, rules (thresholds, sequences,
windows, suppression, grouping), journal chain/tamper/gaps, manifest,
config safety, decoy formats (PDF/DOCX/XLSX/ZIP magic checks), HTML escaping
of attacker strings, response gates and rollback idempotency, parser
fixtures, and full pipeline integration with export/verify round-trips.

## Safe uninstall

```bash
honeytrace decoys clean   # removes ONLY inventory-listed decoys (modified ones preserved as evidence)
honeytrace clean --yes    # removes ONLY HoneyTrace-owned runtime artifacts
sudo systemctl disable --now honeytrace honeytrace-health.timer
```

HoneyTrace never deletes operator configuration, unrelated firewall rules,
or files outside its own manifest.

## License

MIT — see the project header. Synthetic decoy content is generated; never
place real secrets into decoys.
