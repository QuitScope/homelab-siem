# Erwartete Ergebnisse

Deutsch, English below.

Maschinenlesbar: `expect` in [`fixtures/auth-events.jsonl`](fixtures/auth-events.jsonl) und
[`fixtures/expected-correlations.json`](fixtures/expected-correlations.json). Diese Tabelle ist die lesbare Fassung.

| Fixture | Besonderheit | Erwartete Treffer |
|---|---|---|
| `ssh-fail-burst-1..3` | 3 Fehler von 203.0.113.10, 10:00–10:02 | `ssh_auth_failure` (je Event), `ssh_password_guessing` (src 203.0.113.10) |
| `ssh-success` | erfolgreicher Login | – |
| `ssh-fail-spread-1..2` | 2 Fehler von 198.51.100.7, 10 min Abstand | `ssh_auth_failure`, keine Korrelation |
| `ssh-fail-not-normalized` | `action=FAILED` (ungültig, nicht live) | – |
| `ssh-fail-missing-action` | `action` fehlt (ungültig, nicht live) | – |
| `ftp-fail` | Fehler bei `vsftpd` | – |
| `sudo-read-shadow` | `cat /etc/shadow` | `privileged_command` |
| `sudo-append-sudoers-d` | `tee -a /etc/sudoers.d/90-backdoor` | `privileged_command` |
| `sudo-visudo` | `visudo` | `privileged_command` |
| `sudo-benign-apt` | `apt-get update` | – |
| `sudo-read-passwd` | `cat /etc/passwd` | – |
| `sudo-denied-shadow` | `cat /etc/shadow`, `action=failure` | – |
| `sudo-missing-command` | `command` fehlt (ungültig) | – |
| `user-created` | neues Konto `svc-backup` | `user_account_created` |
| `group-created` | neue Gruppe aus demselben useradd | – |
| `user-created-missing-name` | `target_user` fehlt (ungültig) | `user_account_created` |
| `irrelevant-cron` | anderer Event-Typ | – |

## English

Same table: three failures from 203.0.113.10 within one 5-minute bucket must trigger
`ssh_password_guessing`; two failures 10 minutes apart from 198.51.100.7 must not. Successful logins, other
services, sudo commands without sensitive paths, denied sudo attempts, group creation and unrelated events
must not match. Invalid events (`action=FAILED`, missing `action`/`command`) never match; a `user_created`
event without a name is still reported by `user_account_created`.
