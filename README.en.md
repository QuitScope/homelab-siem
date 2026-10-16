# HomeLab SIEM: Cribl Stream + Splunk

[Deutsche Version](README.md)

Authentication events are received by Cribl Stream, normalized (`user`, `src`, `dest`, `action`, `_time`)
and forwarded to Splunk Enterprise via HEC. Splunk provides searches, the
*HomeLab Security Overview* dashboard (with drilldown) and alerts generated from the Sigma rules in [`sigma-detection-lab/`](sigma-detection-lab/README.en.md) (e.g. repeated failed logins).

```
test events ──────HTTP :10080──┐
lab-linux-01 (sshd/rsyslog)    ├─▶ Cribl Stream ──HEC (internal)──▶ Splunk Enterprise
             ──syslog UDP 9514─┘   homelab_auth_normalize            index=homelab_auth
                                   drop debug → parse sshd →         dashboard · alert · drilldown
                                   normalize → JSON
```

Proxmox VMs: `siem-docker` (210, 4 vCPU / 8 GB / 50 GB, Docker) and `lab-linux-01` (211, 1 vCPU / 1 GB,
log source). Result: 72.7 % fewer bytes and 27.3 % fewer events with zero failed logins lost
([measurement](docs/test-results.en.md#data-reduction)).

![Dashboard](docs/screenshots/01-dashboard.jpg)

![Sigma detections on the dashboard](docs/screenshots/06-dashboard-detections.jpg)

| Drilldown to raw event | Triggered alerts | Cribl pipeline | Cribl routes |
|---|---|---|---|
| ![](docs/screenshots/02-drilldown.jpg) | ![](docs/screenshots/03-triggered-alerts.jpg) | ![](docs/screenshots/04-cribl-pipeline.jpg) | ![](docs/screenshots/05-cribl-routes.jpg) |

## Setup

```bash
# on the Proxmox host (or clone an existing cloud-init template)
SSHKEY=/root/key.pub ./scripts/create-vm.sh
# on the VM
curl -fsSL https://get.docker.com | sh
cp .env.example .env              # set SPLUNK_PASSWORD and SPLUNK_HEC_TOKEN (uuidgen)
docker compose up -d              # Splunk needs ~2 min until healthy
set -a; . ./.env; set +a; python3 scripts/cribl-setup.py   # source, pipeline, route, destination
```

| UI | URL | Login |
|---|---|---|
| Cribl Stream | `http://<vm>:9000` | `admin` / `admin`, change on first login (then set `CRIBL_PASSWORD` in `.env`) |
| Splunk | `http://<vm>:8000` | `admin` / `SPLUNK_PASSWORD` from `.env` |

The Splunk side is code in [`splunk/homelab_siem`](splunk/homelab_siem/default): index, `props.conf`,
dashboard, alert and data-quality search. The Cribl side is code in [`scripts/cribl-setup.py`](scripts/cribl-setup.py).
HEC (8088) is not published outside the Docker network.

## Normalization rules (Cribl pipeline `homelab_auth_normalize`)

| Rule | Implementation |
|---|---|
| `_time` from `event_time` | `Date.parse(event_time) / 1000` |
| `user` / `src` / `dest` always set | `user‖username‖user_name`, `src‖src_ip‖rhost`, `dest‖host` |
| one vocabulary for `action` | `failed/denied/error/invalid user → failure`, `accepted/ok/succeeded → success` |
| parse sshd syslog | regex on `Failed …`, `Accepted …`, `Invalid user …` |
| reduce noise, never drop failures | only events with `level=debug` are dropped |

## Tests

```bash
./scripts/send-events.sh 3   # 3 failures in 5 min → alert must fire
./scripts/send-events.sh 2   # 2 failures         → alert must stay quiet
curl --data-binary @data/auth-events.jsonl http://<vm>:10080/cribl/_bulk   # static sample set
python3 scripts/reduction-test.py 1000   # data-reduction measurement (on the VM, .env loaded)
```

Real source: on `lab-linux-01` install `rsyslog` and add
`auth,authpriv.* @<siem-vm>:9514` to `/etc/rsyslog.d/90-cribl.conf`.

See [docs/test-results.en.md](docs/test-results.en.md).

## Detection-as-Code: Sigma Detection Lab

Detections live as Sigma rules in [`sigma-detection-lab/`](sigma-detection-lab/README.en.md): conversion to SPL, tests against synthetic events and GitHub Actions ([workflow](.github/workflows/validate.yml)). For this the Cribl pipeline also normalizes sudo and useradd lines ([schema](sigma-detection-lab/docs/data-schema.en.md)).

## Licenses

Cribl Stream Free (≤ 1 TB/day). The Splunk container starts with the 60-day Enterprise trial;
Splunk Free would disable alerting.
