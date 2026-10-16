# Test results

[Deutsche Version](test-results.md)

Only runs that actually happened. Environment: Windows 11, uv 0.11.30, Python 3.12.13, sigma-cli 3.1.0,
pySigma 1.5.1, pySigma-backend-splunk 2.1.0, pytest 9.1.1.

## Local – 2026-10-15

| Step | Command | Result |
|---|---|---|
| Install | `uv sync --locked` (fresh `.venv`) | ✔ |
| Validation | `./scripts/validate-rules.sh` | 0 errors, 0 issues (4 rules incl. correlation) |
| Conversion | `./scripts/convert-rules.sh` | 4 SPL files + `savedsearches.conf` |
| Tests | `uv run pytest` | **21 passed** |

### Mutation check

Temporarily changed `action: success` to `failure` in `privileged_command.yml` → `test_detections[positive]`,
`test_detections[negative]` and `test_generated_files_are_up_to_date` fail (3 failed, 18 passed); after the
revert 21 passed again. The tests check the rule logic, not hard-coded results.

### Problems found during implementation

| Problem | Fix |
|---|---|
| `sigma check`: ATT&CK tactic tags with underscore (`attack.credential_access`) are invalid in the current Sigma spec | hyphenated form (`attack.credential-access`) |
| The base rule of a correlation was not emitted as its own query | `generate: true` in the correlation |
| sigma-cli 3.1.0 `convert -od -ot '{stem}-{index}.spl'`: `{index}` stays empty, the correlation overwrites the base rule (4 reported, 3 written) | conversion via the pySigma API (`scripts/convert_rules.py`) |
| sigma-cli 3.1.0 `-f savedsearches`: base rule with `generate: true` has no stanza → broken `.conf` | own `savedsearches.conf` generation in the same script |
| pySigma 2.0.1 is incompatible with pySigma-backend-splunk 2.1.0 (backend requires `pysigma<2`) | pinned pySigma 1.5.1 |

## GitHub Actions

| Run | Result |
|---|---|
| first run | ✘ `./scripts/validate-rules.sh: Permission denied` – scripts were committed from Windows without the executable bit |
| after `chmod +x` | ✔ Ubuntu 24.04, Python 3.12.3: validation without issues, conversion without drift, **21 passed** |

## Live in Splunk

Homelab: Cribl Stream + Splunk 10.6 on `siem-docker`, Cribl extension rolled out with `scripts/cribl-setup.py`.

### Fixtures through Cribl → Splunk (2026-10-15, 18:36 UTC)

`python3 sigma-detection-lab/scripts/splunk-live-test.py` – 18 fixtures (2 with `"live": false` skipped),
`host=sigma-live-20261015183606`, every generated SPL query executed in Splunk:

| Rule | Hits in Splunk | Expected | |
|---|---|---|---|
| `privileged_command` | `sudo-append-sudoers-d`, `sudo-read-shadow`, `sudo-visudo` | identical | PASS |
| `ssh_auth_failure` | `ssh-fail-burst-1..3`, `ssh-fail-spread-1..2` | identical | PASS |
| `ssh_password_guessing` | `src=203.0.113.10` | identical | PASS |
| `user_account_created` | `user-created`, `user-created-missing-name` | identical | PASS |

### Real Linux events (lab-linux-01 → rsyslog → Cribl → Splunk)

Test account `labsudo` with a sudoers entry for `/usr/bin/id` and `/usr/bin/cat` only; then `useradd sigmatest`.
Generated SPL scoped to `host=lab-linux-01`, last 10 minutes:

| Action on lab-linux-01 | normalized in Splunk | Rule hit |
|---|---|---|
| `sudo /usr/bin/cat /etc/shadow` | `event_type=sudo user=labsudo target_user=root action=success` | `privileged_command` ✔ |
| `sudo /usr/bin/id` | `event_type=sudo … command=/usr/bin/id` | none ✔ |
| `useradd sigmatest` (`new user`) | `event_type=user_created target_user=sigmatest` | `user_account_created` ✔ |
| same useradd call (`new group`) | `event_type=group_created` | none ✔ |

Afterwards `labsudo`, `sigmatest` and `/etc/sudoers.d/labsudo` were removed again.

### Import as alerts (2026-10-15)

Copied `generated/savedsearches.conf` to `splunk/homelab_siem/local/` on the VM and loaded it via
`saved/searches/_reload` (HTTP 200, no restart). Then at 18:43 UTC on `lab-linux-01`: `sudo cat /etc/shadow`
(as root), `useradd sigmae2e` → `userdel`, 3 SSH logins with unknown users from the workstation.

| Saved Search | scheduled | run 18:45 UTC `result_count` | fired |
|---|---|---|---|
| Sigma - Sudo Command On Credential Or Sudoers Files | yes (high → Severity 4) | 1 | ✔ |
| Sigma - SSH Password Guessing From Single Source | yes (medium → 3) | 1 | ✔ |
| Sigma - Local User Account Created | yes (medium → 3) | 1 | ✔ |
| Sigma - SSH Authentication Failure | no (low) | – | – |

The existing alert "HomeLab - Repeated Failed Logins" fired in the same run as well – the Sigma correlation
`ssh_password_guessing` covers the same case; one of the two can be disabled.

The old alert was then disabled (`enableSched = 0` in `splunk/homelab_siem/default/savedsearches.conf`, loaded
via `_reload`; Splunk reports `is_scheduled=false`). At the same time "HomeLab - Data Quality" was limited to login
events, because sudo/useradd events have no `src` by schema: 1485 events in the last 24 h, 0 with missing fields.
