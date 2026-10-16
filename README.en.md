# Homelab SIEM: Cribl Stream and Splunk

[Deutsche Version](README.md)

I wanted to understand what actually happens in a SOC between "someone tries to log in over SSH" and "an
analyst sees an alert". So I built that chain myself in my Proxmox homelab: Linux hosts send their auth logs
via syslog to Cribl Stream, Cribl brings the events into one format and forwards them over HEC to Splunk.
Splunk has a dashboard with drilldown and alerts that are generated from Sigma rules.

```
test events ──────HTTP :10080──┐
lab-linux-01 (sshd/rsyslog)    ├─▶ Cribl Stream ──HEC (internal)──▶ Splunk Enterprise
             ──syslog UDP 9514─┘   homelab_auth_normalize            index=homelab_auth
                                   drop debug → parse sshd →         dashboard · alert · drilldown
                                   normalise → JSON
```

It runs on two VMs: `siem-docker` (VM 210, 4 vCPU, 8 GB, Docker) with Cribl and Splunk, and `lab-linux-01`
(VM 211, 1 vCPU, 1 GB) as a real log source.

![Dashboard](docs/screenshots/01-dashboard.jpg)

![Sigma detections in the dashboard](docs/screenshots/06-dashboard-detections.jpg)

| Drilldown to raw event | Triggered alerts | Cribl pipeline | Cribl routes |
|---|---|---|---|
| ![](docs/screenshots/02-drilldown.jpg) | ![](docs/screenshots/03-triggered-alerts.jpg) | ![](docs/screenshots/04-cribl-pipeline.jpg) | ![](docs/screenshots/05-cribl-routes.jpg) |

## Why it is built this way

- **Cribl in front of Splunk:** I wanted to normalise the data before it hits the index instead of building
  every search around field variants. Whether an event brings `username`, `user_name` or `user`, in Splunk the
  field is always `user`. It also lets me measure how much volume a pipeline saves: with my test data it was
  72.7 % fewer bytes and 27.3 % fewer events, without losing a single failed login
  ([measurement](docs/test-results.en.md#data-reduction)).
- **Never drop failures:** the pipeline only drops debug heartbeats. A failed login lost in a noise filter would
  be exactly the event you go looking for later.
- **Configuration as code:** the Splunk app (index, `props.conf`, dashboard, alerts) lives in
  [`splunk/homelab_siem`](splunk/homelab_siem/default), and [`scripts/cribl-setup.py`](scripts/cribl-setup.py)
  builds the Cribl configuration through its API. That way I can throw the stack away and set it up again
  without clicking through two UIs.
- **Detections as Sigma rules:** the rules should not depend on Splunk. In the
  [Sigma Detection Lab](sigma-detection-lab/README.en.md) they are converted to SPL, checked against test events
  and validated in GitHub Actions.
- **HEC internal only:** port 8088 is only reachable inside the Docker network. From outside, the only way into
  Splunk is through Cribl.

## Setup

The commands run on the VM `siem-docker`; the docs refer to its address as `<VM-IP>`.

```bash
# on the Proxmox host (or clone an existing cloud-init template)
SSHKEY=/root/key.pub ./scripts/create-vm.sh
# on the VM
curl -fsSL https://get.docker.com | sh
cp .env.example .env              # set SPLUNK_PASSWORD and SPLUNK_HEC_TOKEN (uuidgen)
docker compose up -d              # Splunk needs about 2 minutes to become "healthy"
set -a; . ./.env; set +a; python3 scripts/cribl-setup.py   # source, pipeline, route, destination
```

Cribl is then reachable at `http://<VM-IP>:9000` (change the default password on first login and put it into
`CRIBL_PASSWORD`), Splunk at `http://<VM-IP>:8000` with the password from `.env`.

As a real source, `lab-linux-01` gets rsyslog and the line `auth,authpriv.* @<VM-IP>:9514` in
`/etc/rsyslog.d/90-cribl.conf`. New VMs are now set up with Ansible, see
[homelab-infrastructure-automation](https://github.com/QuitScope/homelab-infrastructure-automation).

## What the pipeline normalises

| Rule | Implementation |
|---|---|
| `_time` from `event_time` | `Date.parse(event_time) / 1000` |
| `user`, `src`, `dest` always set | `user‖username‖user_name`, `src‖src_ip‖rhost`, `dest‖host` |
| one vocabulary for `action` | `failed/denied/error/invalid user → failure`, `accepted/ok/succeeded → success` |
| parse sshd syslog | regex on `Failed …`, `Accepted …`, `Invalid user …` |
| reduce noise | only events with `level=debug` are dropped |

## Testing

```bash
./scripts/send-events.sh 3   # 3 failures in 5 minutes, the alert must fire
./scripts/send-events.sh 2   # 2 failures, the alert must stay quiet
curl --data-binary @data/auth-events.jsonl http://<VM-IP>:10080/cribl/_bulk   # static sample set
python3 scripts/reduction-test.py 1000   # data reduction measurement (on the VM, .env loaded)
```

All results with the actual numbers are in [docs/test-results.en.md](docs/test-results.en.md).

## What went wrong and what I learned

- **`host` existed twice in Splunk.** Splunk sets `host` from the index metadata and also extracted it from the
  JSON, so the field became multivalued and statistics counted wrong. Cribl no longer writes `host` into
  `_raw`. Lesson: in Splunk, always check which fields already exist as metadata.
- **sigma-cli was less finished than it looked.** `convert -od` wrote the correlation rule over its base rule,
  and the `savedsearches` format produced broken `.conf` files for correlations. I now convert through the
  pySigma API in my own script. On top of that, pySigma 2 does not work with the Splunk backend, so 1.5.1 is
  pinned.
- **The first CI run failed on file permissions.** Scripts committed from Windows had no executable bit. Since
  then I use `git update-index --chmod=+x` and a `.gitattributes` with `eol=lf`.
- **Splunk Free cannot alert.** The container therefore runs with the 60-day Splunk Enterprise trial licence.
  Cribl Stream runs in the free tier (up to 1 TB per day).
- **Fixed 5-minute windows have a gap:** an attack that runs exactly across a window boundary is not detected.
  Good enough for the homelab; a sliding window with `streamstats` would be cleaner.
