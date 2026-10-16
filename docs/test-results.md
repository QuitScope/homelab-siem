# Testergebnisse vom 15.10.2026

[English version](test-results.en.md)

Umgebung: Proxmox VE 9.2, VM `siem-docker` (VMID 210, 4 vCPU / 8 GB / 50 GB), Docker Compose v5,
`cribl/cribl:latest`, `splunk/splunk:latest` (Enterprise-Testlizenz).

| # | Test | Eingabe | Erwartet | Ergebnis |
|---|---|---|---|---|
| 1 | Ingestion | `data/auth-events.jsonl` (5) + `send-events.sh 3` (5) | 10 Events in `homelab_auth` | 10 |
| 2 | Zeitstempel | `event_time=2026-10-15T10:01:00Z` | `_time` = 10:01:00 UTC | ok |
| 3 | Alert positiv | 3 Fehler von `192.0.2.20` in 5 Min | Alert löst aus | Scheduler 17:00: `result_count=1`, `logevent` |
| 4 | Alert negativ | 2 Fehler von `192.0.2.20` in 5 Min | kein Alert | Scheduler 17:05: `result_count=0` |
| 5 | Normalisierung | `action=FAILED`, `username`, `src_ip`, kein `dest` | `failure`, `user`, `src`, `dest=host` | ok |
| 6 | Rauschfilter | Event mit `level=debug` | in Cribl verworfen | nicht indexiert |
| 7 | Datenqualität | Suche *HomeLab - Data Quality* | 0 fehlende Felder | 10 Events, 0 fehlend |

Gefundener und behobener Fehler: `host` war in Splunk mehrwertig (Index-Metadaten + JSON-Extraktion).
`host` wird nicht mehr in `_raw` geschrieben; Nachtest: `mvcount(host)=1`.

## Echte SSH-Logs (lab-linux-01 → rsyslog UDP 9514 → Cribl)

Vom Arbeitsplatz-PC (`<admin-pc>`): drei Anmeldeversuche mit unbekannten Benutzern (`mallory`, `eve`,
`oscar`) und eine schlüsselbasierte root-Anmeldung an `lab-linux-01`.

| sshd-Zeile | Splunk (`homelab_auth`) |
|---|---|
| `Invalid user mallory from <admin-pc> port …` | `user=mallory src=<admin-pc> action=failure service=ssh` |
| `Accepted publickey for root from <admin-pc> port …` | `user=root src=<admin-pc> action=success service=ssh` |

sshd-Zeilen ohne Anmeldebezug und sonstiger Syslog-Verkehr treffen keine Route und werden nicht weitergeleitet.

Alert auf echten Logs: Scheduler-Lauf 17:20 UTC `result_count=1` →
`ALERT repeated failed logins src=<admin-pc> dest=lab-linux-01 failures=3` (Lauf 17:15 vor dem Test: 0).

<a id="data-reduction"></a>
## Data Reduction

`python3 scripts/reduction-test.py 1000`: 1000 synthetische Agent-Events (fester Seed 42, 25 % Debug-Heartbeats,
Agent-Metadaten an jedem Event). Cribl klont jedes Event: unverändertes JSON → `homelab_baseline`,
optimiert → `homelab_auth`. Gemessen in Splunk mit `sum(len(_raw))`.

| Pipeline | Events | Bytes (_raw) | Bytes/Event |
|---|---|---|---|
| unverändert (homelab_baseline) | 1000 | 416106 | 416 |
| optimiert (homelab_auth) | 727 | 113655 | 156 |
| Reduktion | 27,3 % | 72,7 % | |

Fehlgeschlagene Anmeldungen: Baseline 466, optimiert 466, keine verworfen (das Skript prüft das per `assert`).
Die Event-Reduktion stammt nur aus den Debug-Heartbeats; die Byte-Reduktion überwiegend aus entfernten
Agent-Metadaten (`pid`, `agent.*`, `session_id`, `labels`, `debug_trace`, `message`). Die von Splunk
lizenzierte Ingestion kann leicht von `len(_raw)` abweichen.

Screenshots: [docs/screenshots](screenshots) (Dashboard-Zeitraum 17:02 UTC bis jetzt, also ohne die Messläufe).
