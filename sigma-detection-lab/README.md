# Sigma Detection Lab

[English version](README.en.md)

Detection-as-Code für das [HomeLab SIEM](../README.md): Security-Detections werden als Sigma-Regeln
gepflegt, mit dem offiziellen pySigma-Splunk-Backend in SPL übersetzt und **gegen synthetische Events
getestet** – lokal, in GitHub Actions und optional live in Splunk.

```
Linux-Logs ──▶ Cribl Stream (Normalisierung) ──▶ Splunk index=homelab_auth
                                                      ▲
rules/*.yml ──pySigma──▶ generated/*.spl ──Import─────┘
```

| Regel | Erkennt | Level | ATT&CK |
|---|---|---|---|
| `ssh_auth_failure` | fehlgeschlagene SSH-Anmeldung | low | T1110.001 |
| `ssh_password_guessing` | ≥ 3 SSH-Fehler einer Quelle in 5 min (Sigma-Korrelation) | medium | T1110.001 |
| `privileged_command` | sudo auf `/etc/shadow`, `/etc/gshadow`, sudoers, `visudo` | high | T1003.008, T1548.003 |
| `user_account_created` | neues lokales Konto (useradd) | medium | T1136.001 |

Details: [Detection-Katalog](docs/detection-catalog.md) · [Event-Schema](docs/data-schema.md) ·
[ATT&CK-Abdeckung](docs/mitre-coverage.md) · [Architektur](docs/architecture.md) ·
[Testergebnisse](docs/test-results.md)

## Einrichtung

Paketmanager ist [uv](https://docs.astral.sh/uv/) (getestet mit 0.11.30). Alle Versionen sind in
`pyproject.toml` fixiert und in `uv.lock` gesperrt; installiert wird nur in `.venv/` dieses Ordners.

```bash
cd sigma-detection-lab
uv sync --locked          # Python 3.12 + sigma-cli 3.1.0, pySigma 1.5.1, pySigma-backend-splunk 2.1.0, pytest
```

## Prüfen, konvertieren, testen

```bash
./scripts/validate-rules.sh   # sigma check --fail-on-issues (Syntax, Metadaten, ATT&CK-Tags)
./scripts/convert-rules.sh    # rules/ -> generated/spl/*.spl + generated/savedsearches.conf
uv run pytest                 # lokale Tests: Metadaten, Konvertierung, Drift, Detection-Logik
```

`generated/` wird nie von Hand bearbeitet: Tests und CI schlagen fehl, wenn die Dateien nicht exakt der
Konvertierung von `rules/` entsprechen. Warum ein eigenes Python-Skript statt `sigma convert -od`:
siehe Kopf von [`scripts/convert_rules.py`](scripts/convert_rules.py).

### Live-Test in Splunk (optional, nicht in CI)

Benötigt den laufenden Homelab-Stack. Auf der Docker-VM im Repo-Checkout:

```bash
set -a; . /opt/homelab-siem/.env; set +a
python3 sigma-detection-lab/scripts/splunk-live-test.py
```

Das Skript schickt die Fixtures (mit eindeutigem `host`) durch Cribl nach Splunk, führt jede generierte
SPL aus und vergleicht die Treffer mit den erwarteten Fixture-IDs.

## SPL in Splunk übernehmen (manuell)

Kein automatisches Deployment: CI hat keinen Zugang zum Homelab. Sicherer manueller Weg:

1. Einzeln über die Oberfläche: Inhalt aus `generated/spl/<regel>.spl` in *Search & Reporting* einfügen,
   prüfen, dann *Save As → Alert* (Zeitplan und Aktion dort festlegen).
2. Alle auf einmal per Datei (Admin-Zugang zur VM nötig): `generated/savedsearches.conf` nach
   `splunk/homelab_siem/local/savedsearches.conf` im Homelab-Repo auf der VM kopieren
   (`/opt/homelab-siem/...`, per Bind-Mount in Splunk), dann neu laden:
   `curl -k -u admin -X POST https://localhost:8089/servicesNS/nobody/homelab_siem/saved/searches/_reload`
   (im Splunk-Container) oder `docker compose restart splunk`.
   Regeln ab Level `medium` werden als Alert geplant (alle 5 Minuten über die letzten 5 Minuten, sichtbar unter
   *Activity → Triggered Alerts*); `low`-Regeln bleiben ungeplante Saved Searches. E-Mail/Webhook-Aktionen
   bei Bedarf in Splunk ergänzen. Im Homelab ist das so eingespielt (siehe Testergebnisse).

Index und Sourcetype stehen in [`pipelines/splunk/homelab.yml`](pipelines/splunk/homelab.yml).

## Erweitern

1. Neue Regel unter `rules/linux/` anlegen (eindeutige `id` per `uuidgen`, `name`, ATT&CK-Tags und passender
   `references`-Link, `falsepositives`, Beschreibung mit Datenquelle und Pflichtfeldern).
2. Braucht sie neue Felder: in [`docs/data-schema.md`](docs/data-schema.md), `tests/schema.py`,
   der Pipeline (`schema_guard`) und der Cribl-Normalisierung ergänzen.
3. Mindestens einen positiven und einen negativen Fixture aus derselben Quelle in
   `tests/fixtures/auth-events.jsonl` hinzufügen.
4. `./scripts/validate-rules.sh && ./scripts/convert-rules.sh && uv run pytest`, `generated/` mit committen.

## Annahmen

- Die Events kommen bereits normalisiert über die Cribl-Pipeline aus dem Homelab-Repo
  ([`../scripts/cribl-setup.py`](../scripts/cribl-setup.py)) in `index=homelab_auth`, `sourcetype=homelab:auth`.
- Linux-Quellen schicken `auth,authpriv.*` per rsyslog an Cribl (UDP 9514).
- Wer eine andere Normalisierung nutzt, muss nur `pipelines/splunk/homelab.yml` (Index/Sourcetype) bzw. ein
  Feld-Mapping ergänzen; die lokalen Tests sind davon unabhängig.
