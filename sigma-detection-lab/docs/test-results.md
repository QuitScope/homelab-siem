# Testergebnisse

[English version](test-results.en.md)

Nur tatsächlich ausgeführte Läufe. Umgebung: Windows 11, uv 0.11.30, Python 3.12.13, sigma-cli 3.1.0,
pySigma 1.5.1, pySigma-backend-splunk 2.1.0, pytest 9.1.1.

## Lokal – 15.10.2026

| Schritt | Befehl | Ergebnis |
|---|---|---|
| Installation | `uv sync --locked` (frische `.venv`) | ✔ |
| Validierung | `./scripts/validate-rules.sh` | 0 Fehler, 0 Issues (4 Regeln inkl. Korrelation) |
| Konvertierung | `./scripts/convert-rules.sh` | 4 SPL-Dateien + `savedsearches.conf` |
| Tests | `uv run pytest` | **21 passed** |

### Gegenprobe (Mutation)

`action: success` in `privileged_command.yml` testweise auf `failure` geändert → `test_detections[positive]`,
`test_detections[negative]` und `test_generated_files_are_up_to_date` schlagen fehl (3 failed, 18 passed);
nach dem Zurücksetzen wieder 21 passed. Die Tests prüfen also die Regellogik und nicht fest einprogrammierte
Ergebnisse.

### Bei der Umsetzung gefundene Probleme

| Problem | Lösung |
|---|---|
| `sigma check`: ATT&CK-Taktik-Tags mit Unterstrich (`attack.credential_access`) sind laut aktueller Sigma-Spezifikation ungültig | Bindestrich-Schreibweise (`attack.credential-access`) |
| Basisregel einer Korrelation wurde nicht als eigene Abfrage ausgegeben | `generate: true` in der Korrelation |
| sigma-cli 3.1.0 `convert -od -ot '{stem}-{index}.spl'`: `{index}` bleibt leer, die Korrelation überschreibt die Basisregel (4 gemeldet, 3 geschrieben) | Konvertierung über die pySigma-API (`scripts/convert_rules.py`) |
| sigma-cli 3.1.0 `-f savedsearches`: Basisregel mit `generate: true` ohne Stanza → kaputte `.conf` | eigene `savedsearches.conf`-Erzeugung im selben Skript |
| pySigma 2.0.1 ist mit pySigma-backend-splunk 2.1.0 nicht kompatibel (Backend verlangt `pysigma<2`) | pySigma 1.5.1 fixiert |

## GitHub Actions

| Lauf | Ergebnis |
|---|---|
| erster Lauf | ✘ `./scripts/validate-rules.sh: Permission denied` – Skripte waren unter Windows ohne Executable-Bit committet |
| nach `chmod +x` | ✔ Ubuntu 24.04, Python 3.12.3: Validierung ohne Issues, Konvertierung ohne Drift, **21 passed** |

## Live in Splunk

Homelab: Cribl Stream + Splunk 10.6 auf `siem-docker`, Cribl-Erweiterung per `scripts/cribl-setup.py` ausgerollt.

### Fixtures durch Cribl → Splunk (15.10.2026, 18:36 UTC)

`python3 sigma-detection-lab/scripts/splunk-live-test.py` – 18 Fixtures (2 mit `"live": false` ausgelassen),
`host=sigma-live-20261015183606`, jede generierte SPL in Splunk ausgeführt:

| Regel | Treffer in Splunk | Erwartet | |
|---|---|---|---|
| `privileged_command` | `sudo-append-sudoers-d`, `sudo-read-shadow`, `sudo-visudo` | identisch | PASS |
| `ssh_auth_failure` | `ssh-fail-burst-1..3`, `ssh-fail-spread-1..2` | identisch | PASS |
| `ssh_password_guessing` | `src=203.0.113.10` | identisch | PASS |
| `user_account_created` | `user-created`, `user-created-missing-name` | identisch | PASS |

### Echte Linux-Ereignisse (lab-linux-01 → rsyslog → Cribl → Splunk)

Testkonto `labsudo` mit sudoers-Freigabe nur für `/usr/bin/id` und `/usr/bin/cat`; danach `useradd sigmatest`.
Generierte SPL mit `host=lab-linux-01`, letzte 10 Minuten:

| Aktion auf lab-linux-01 | normalisiert in Splunk | Regel-Treffer |
|---|---|---|
| `sudo /usr/bin/cat /etc/shadow` | `event_type=sudo user=labsudo target_user=root action=success` | `privileged_command` ✔ |
| `sudo /usr/bin/id` | `event_type=sudo … command=/usr/bin/id` | keiner ✔ |
| `useradd sigmatest` (`new user`) | `event_type=user_created target_user=sigmatest` | `user_account_created` ✔ |
| dieselbe useradd-Ausführung (`new group`) | `event_type=group_created` | keiner ✔ |

Danach wurden `labsudo`, `sigmatest` und `/etc/sudoers.d/labsudo` wieder entfernt.

### Import als Alerts (15.10.2026)

`generated/savedsearches.conf` nach `splunk/homelab_siem/local/` auf der VM kopiert und per
`saved/searches/_reload` geladen (HTTP 200, kein Neustart). Danach um 18:43 UTC auf `lab-linux-01`:
`sudo cat /etc/shadow` (als root), `useradd sigmae2e` → `userdel`, 3 SSH-Logins mit
unbekannten Benutzern vom Arbeitsplatz-PC.

| Saved Search | geplant | Lauf 18:45 UTC `result_count` | ausgelöst |
|---|---|---|---|
| Sigma - Sudo Command On Credential Or Sudoers Files | ja (high → Severity 4) | 1 | ✔ |
| Sigma - SSH Password Guessing From Single Source | ja (medium → 3) | 1 | ✔ |
| Sigma - Local User Account Created | ja (medium → 3) | 1 | ✔ |
| Sigma - SSH Authentication Failure | nein (low) | – | – |

Der bestehende Alert „HomeLab - Repeated Failed Logins“ hat im selben Lauf ebenfalls ausgelöst – die
Sigma-Korrelation `ssh_password_guessing` deckt denselben Fall ab; einer der beiden kann deaktiviert werden.

Daraufhin wurde der alte Alert deaktiviert (`enableSched = 0` in `splunk/homelab_siem/default/savedsearches.conf`,
per `_reload` geladen; Splunk meldet `is_scheduled=false`). Gleichzeitig wurde „HomeLab - Data Quality“ auf
Anmelde-Events beschränkt, weil sudo/useradd-Events laut Schema kein `src` haben: 1485 Events der letzten
24 h, 0 mit fehlenden Feldern.
