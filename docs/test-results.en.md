# Test results, 2026-10-15

[Deutsche Version](test-results.md)

Environment: Proxmox VE 9.2, VM `siem-docker` (VMID 210, 4 vCPU / 8 GB / 50 GB), Docker Compose v5,
`cribl/cribl:latest`, `splunk/splunk:latest` (Enterprise trial).

| # | Test | Input | Expected | Result |
|---|---|---|---|---|
| 1 | Ingestion | `data/auth-events.jsonl` (5) + `send-events.sh 3` (5) | 10 events in `homelab_auth` | 10 |
| 2 | Timestamp | `event_time=2026-10-15T10:01:00Z` | `_time` = 10:01:00 UTC | ok |
| 3 | Alert positive | 3 failures from `192.0.2.20` within 5 min | alert fires | scheduler 17:00: `result_count=1`, `logevent` |
| 4 | Alert negative | 2 failures from `192.0.2.20` within 5 min | no alert | scheduler 17:05: `result_count=0` |
| 5 | Normalization | `action=FAILED`, `username`, `src_ip`, no `dest` | `failure`, `user`, `src`, `dest=host` | ok |
| 6 | Noise filter | event with `level=debug` | dropped in Cribl | not indexed |
| 7 | Data quality | search *HomeLab - Data Quality* | 0 missing fields | 10 events, 0 missing |

Bug found and fixed: `host` was multivalue in Splunk (index-time metadata + JSON extraction).
`host` is no longer written into `_raw`; re-test: `mvcount(host)=1`.

## Real SSH logs (lab-linux-01 → rsyslog UDP 9514 → Cribl)

From the workstation (`<admin-pc>`): three logins with unknown users (`mallory`, `eve`, `oscar`) and one
key-based root login against `lab-linux-01`.

| sshd line | Splunk (`homelab_auth`) |
|---|---|
| `Invalid user mallory from <admin-pc> port …` | `user=mallory src=<admin-pc> action=failure service=ssh` |
| `Accepted publickey for root from <admin-pc> port …` | `user=root src=<admin-pc> action=success service=ssh` |

Non-auth sshd lines and all other syslog traffic hit no route and are not forwarded.

Alert on real logs: scheduler run 17:20 UTC `result_count=1` →
`ALERT repeated failed logins src=<admin-pc> dest=lab-linux-01 failures=3` (17:15 run before the test: 0).

## Data reduction

`python3 scripts/reduction-test.py 1000`: 1000 synthetic agent events (fixed seed 42, 25 % debug heartbeats,
agent metadata on every event). Cribl clones each event: unchanged JSON → `homelab_baseline`,
optimized → `homelab_auth`. Measured in Splunk with `sum(len(_raw))`.

| Pipeline | Events | Bytes (_raw) | Bytes/Event |
|---|---|---|---|
| unchanged (homelab_baseline) | 1000 | 416106 | 416 |
| optimized (homelab_auth) | 727 | 113655 | 156 |
| reduction | 27.3 % | 72.7 % | |

Failed logins: baseline 466, optimized 466, none dropped (the script asserts this).
Event reduction comes only from debug heartbeats; byte reduction mostly from dropping agent metadata
(`pid`, `agent.*`, `session_id`, `labels`, `debug_trace`, `message`). Splunk's licensed ingest can differ
slightly from `len(_raw)`.

Screenshots: [docs/screenshots](screenshots) (dashboard time range 17:02 UTC → now, i.e. without the
measurement runs).
