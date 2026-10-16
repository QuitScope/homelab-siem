# HomeLab SIEM: Cribl Stream + Splunk

[English version](README.en.md)

Authentifizierungsereignisse werden von Cribl Stream empfangen, normalisiert (`user`, `src`, `dest`,
`action`, `_time`) und per HEC an Splunk Enterprise weitergegeben. Splunk liefert Suchen, das Dashboard
*HomeLab Security Overview* (mit Drilldown) und Alerts aus den Sigma-Regeln in [`sigma-detection-lab/`](sigma-detection-lab/README.md) (u. a. wiederholte fehlgeschlagene Anmeldungen).

```
Testevents ───────HTTP :10080──┐
lab-linux-01 (sshd/rsyslog)    ├─▶ Cribl Stream ──HEC (intern)──▶ Splunk Enterprise
             ──Syslog UDP 9514─┘   homelab_auth_normalize          index=homelab_auth
                                   Debug verwerfen → sshd parsen → Dashboard · Alert · Drilldown
                                   normalisieren → JSON
```

Proxmox-VMs: `siem-docker` (210, 4 vCPU / 8 GB / 50 GB, Docker) und `lab-linux-01` (211, 1 vCPU / 1 GB,
Logquelle). Ergebnis: 72,7 % weniger Bytes und 27,3 % weniger Events, ohne eine einzige fehlgeschlagene
Anmeldung zu verlieren ([Messung](docs/test-results.md#data-reduction)).

![Dashboard](docs/screenshots/01-dashboard.jpg)

![Sigma-Detections im Dashboard](docs/screenshots/06-dashboard-detections.jpg)

| Drilldown auf Rohevent | Ausgelöste Alerts | Cribl-Pipeline | Cribl-Routen |
|---|---|---|---|
| ![](docs/screenshots/02-drilldown.jpg) | ![](docs/screenshots/03-triggered-alerts.jpg) | ![](docs/screenshots/04-cribl-pipeline.jpg) | ![](docs/screenshots/05-cribl-routes.jpg) |

## Einrichtung

```bash
# auf dem Proxmox-Host (oder ein vorhandenes Cloud-Init-Template klonen)
SSHKEY=/root/key.pub ./scripts/create-vm.sh
# auf der VM
curl -fsSL https://get.docker.com | sh
cp .env.example .env              # SPLUNK_PASSWORD und SPLUNK_HEC_TOKEN (uuidgen) setzen
docker compose up -d              # Splunk braucht ca. 2 Minuten bis "healthy"
set -a; . ./.env; set +a; python3 scripts/cribl-setup.py   # Source, Pipeline, Route, Destination
```

| Oberfläche | URL | Login |
|---|---|---|
| Cribl Stream | `http://<vm>:9000` | `admin` / `admin`, beim ersten Login ändern (danach `CRIBL_PASSWORD` in `.env`) |
| Splunk | `http://<vm>:8000` | `admin` / `SPLUNK_PASSWORD` aus `.env` |

Die Splunk-Seite liegt als Code in [`splunk/homelab_siem`](splunk/homelab_siem/default): Index, `props.conf`,
Dashboard, Alert und Datenqualitäts-Suche. Die Cribl-Seite liegt als Code in
[`scripts/cribl-setup.py`](scripts/cribl-setup.py). HEC (8088) ist nur im Docker-Netz erreichbar.

## Normalisierungsregeln (Cribl-Pipeline `homelab_auth_normalize`)

| Regel | Umsetzung |
|---|---|
| `_time` aus `event_time` | `Date.parse(event_time) / 1000` |
| `user` / `src` / `dest` immer befüllt | `user‖username‖user_name`, `src‖src_ip‖rhost`, `dest‖host` |
| einheitliches Vokabular für `action` | `failed/denied/error/invalid user → failure`, `accepted/ok/succeeded → success` |
| sshd-Syslog parsen | Regex auf `Failed …`, `Accepted …`, `Invalid user …` |
| Rauschen reduzieren, Fehler nie verwerfen | nur Events mit `level=debug` werden verworfen |

## Tests

```bash
./scripts/send-events.sh 3   # 3 Fehler in 5 Min → Alert muss auslösen
./scripts/send-events.sh 2   # 2 Fehler          → Alert muss still bleiben
curl --data-binary @data/auth-events.jsonl http://<vm>:10080/cribl/_bulk   # statischer Beispieldatensatz
python3 scripts/reduction-test.py 1000   # Data-Reduction-Messung (auf der VM, .env geladen)
```

Echte Quelle: auf `lab-linux-01` `rsyslog` installieren und
`auth,authpriv.* @<siem-vm>:9514` in `/etc/rsyslog.d/90-cribl.conf` eintragen.

Ergebnisse: [docs/test-results.md](docs/test-results.md).

## Detection-as-Code: Sigma Detection Lab

Die Detections liegen als Sigma-Regeln in [`sigma-detection-lab/`](sigma-detection-lab/README.md): Konvertierung nach SPL, Tests gegen synthetische Events und GitHub Actions ([Workflow](.github/workflows/validate.yml)). Die Cribl-Pipeline normalisiert dafür zusätzlich sudo- und useradd-Zeilen ([Schema](sigma-detection-lab/docs/data-schema.md)).

## Lizenzen

Cribl Stream Free (≤ 1 TB/Tag). Der Splunk-Container startet mit der 60-Tage-Enterprise-Testlizenz;
mit Splunk Free wäre Alerting deaktiviert.
