# Sigma Detection Lab

[Deutsche Version](README.md)

Detection-as-Code for the [HomeLab SIEM](../README.en.md): security detections are maintained as **Sigma
rules**, converted to SPL with the official pySigma Splunk backend and **tested against synthetic
events** – locally, in GitHub Actions and optionally live in Splunk.

```
Linux logs ──▶ Cribl Stream (normalization) ──▶ Splunk index=homelab_auth
                                                      ▲
rules/*.yml ──pySigma──▶ generated/*.spl ──import─────┘
```

| Rule | Detects | Level | ATT&CK |
|---|---|---|---|
| `ssh_auth_failure` | failed SSH authentication | low | T1110.001 |
| `ssh_password_guessing` | ≥ 3 SSH failures from one source in 5 min (Sigma correlation) | medium | T1110.001 |
| `privileged_command` | sudo on `/etc/shadow`, `/etc/gshadow`, sudoers, `visudo` | high | T1003.008, T1548.003 |
| `user_account_created` | new local account (useradd) | medium | T1136.001 |

Details: [detection catalog](docs/detection-catalog.en.md) · [event schema](docs/data-schema.en.md) ·
[ATT&CK coverage](docs/mitre-coverage.en.md) · [architecture](docs/architecture.en.md) ·
[test results](docs/test-results.en.md)

## Setup

Package manager is [uv](https://docs.astral.sh/uv/) (tested with 0.11.30). All versions are pinned in
`pyproject.toml` and locked in `uv.lock`; everything installs into this folder's `.venv/` only.

```bash
cd sigma-detection-lab
uv sync --locked          # Python 3.12 + sigma-cli 3.1.0, pySigma 1.5.1, pySigma-backend-splunk 2.1.0, pytest
```

## Validate, convert, test

```bash
./scripts/validate-rules.sh   # sigma check --fail-on-issues (syntax, metadata, ATT&CK tags)
./scripts/convert-rules.sh    # rules/ -> generated/spl/*.spl + generated/savedsearches.conf
uv run pytest                 # local tests: metadata, conversion, drift, detection logic
```

Never edit `generated/` by hand: tests and CI fail if the files are not exactly the conversion of `rules/`.
Why a Python script instead of `sigma convert -od`: see the header of
[`scripts/convert_rules.py`](scripts/convert_rules.py).

### Live test in Splunk (optional, not in CI)

Needs the running homelab stack. On the Docker VM in the repo checkout:

```bash
set -a; . /opt/homelab-siem/.env; set +a
python3 sigma-detection-lab/scripts/splunk-live-test.py
```

The script sends the fixtures (with a unique `host`) through Cribl to Splunk, runs every generated SPL query
and compares the hits with the expected fixture ids.

## Importing the SPL into Splunk (manual)

No automatic deployment: CI has no access to the homelab. Safe manual paths:

1. One by one in the UI: paste `generated/spl/<rule>.spl` into *Search & Reporting*, review, then
   *Save As → Alert* (set schedule and action there).
2. All at once as a file (needs admin access to the VM): copy `generated/savedsearches.conf` to
   `splunk/homelab_siem/local/savedsearches.conf` of the homelab repo on the VM (`/opt/homelab-siem/...`,
   bind-mounted into Splunk), then reload:
   `curl -k -u admin -X POST https://localhost:8089/servicesNS/nobody/homelab_siem/saved/searches/_reload`
   (inside the Splunk container) or `docker compose restart splunk`.
   Rules of level `medium` and above are scheduled as alerts (every 5 minutes over the last 5 minutes, listed
   under *Activity → Triggered Alerts*); `low` rules stay unscheduled saved searches. Add email/webhook actions
   in Splunk if needed. This is how it is deployed in the homelab (see test results).

Index and sourcetype are set in [`pipelines/splunk/homelab.yml`](pipelines/splunk/homelab.yml).

## Extending

1. Add a rule under `rules/linux/` (unique `id` via `uuidgen`, `name`, ATT&CK tags and the matching
   `references` link, `falsepositives`, description with data source and required fields).
2. New fields: add them to [`docs/data-schema.en.md`](docs/data-schema.en.md), `tests/schema.py`, the pipeline
   (`schema_guard`) and the Cribl normalization.
3. Add at least one positive and one same-source negative fixture to `tests/fixtures/auth-events.jsonl`.
4. `./scripts/validate-rules.sh && ./scripts/convert-rules.sh && uv run pytest`, commit `generated/` too.

## Assumptions

- Events arrive normalized by the Cribl pipeline of the homelab repo
  ([`../scripts/cribl-setup.py`](../scripts/cribl-setup.py)) in `index=homelab_auth`, `sourcetype=homelab:auth`.
- Linux sources forward `auth,authpriv.*` via rsyslog to Cribl (UDP 9514).
- A different normalization only needs changes in `pipelines/splunk/homelab.yml` (index/sourcetype) or a field
  mapping there; the local tests do not depend on it.
