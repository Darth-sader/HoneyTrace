# Evaluation corpus

Deterministic, replayable event traces used to compare detection rulesets
and false-positive behavior. All content is synthetic; timestamps are fixed
(2026-10-11T14:00Z base) so replays are reproducible regardless of wall
clock - the rules engine evaluates on EVENT time.

| File                       | Content                                        | Expected outcome (shipped rules.yml)     |
|----------------------------|------------------------------------------------|------------------------------------------|
| `benign.jsonl`             | Normal admin session: edit a file, allowed outbound | No incidents                      |
| `attack_decoy_read.jsonl`  | SSH login, recon chain (whoami/id/uname), decoy opens, canary callback | R-DECOY-001, R-SESSION-004, R-RECON-005, R-CANARY-010 |
| `attack_bulk.jsonl`        | 25 file opens in ~25 s from one session        | R-BULK-002                                |
| `attack_exfil.jsonl`       | Staging into /tmp then outbound connection     | R-EXFIL-011 (plus R-NET-008)              |

Replay:

    honeytrace replay tests/scenarios/attack_decoy_read.jsonl

or via pytest: `pytest tests/integration/test_replay_corpus.py`.

To add a scenario: record events in the normalized raw-event shape (one JSON
object per line - the same shape collectors emit), give the session a stable
`session_id`, and document the expected rule outcome here. Keep timestamps
in the fixed base window so replays stay deterministic.
