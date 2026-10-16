# Architecture

[Deutsche Version](architecture.md)

```
 Data path (homelab, already running)                    Detection-as-Code (this project)
 ─────────────────────────────────────                   ──────────────────────────────────
 lab-linux-01                                            rules/linux/*.yml   (Sigma, source of truth)
   sshd / sudo / useradd → /var/log/auth.log                    │
   rsyslog  auth,authpriv.* → UDP 9514                          │ pySigma + Splunk backend
        │                                                       │ + pipelines/splunk/homelab.yml
        ▼                                                       ▼   (index, sourcetype, schema guard)
 Cribl Stream (siem-docker)                              generated/spl/*.spl
   route homelab_auth                                    generated/savedsearches.conf
   pipeline homelab_auth_normalize:                             │
     parse sshd/sudo/useradd → schema fields                    │ manual import (see README)
     → JSON _raw                                                ▼
        │  HEC (Docker network only)                     Splunk: saved searches / alerts
        ▼                                                  on index=homelab_auth
 Splunk Enterprise  index=homelab_auth  sourcetype=homelab:auth  ◀──────┘
```

## Components

| Part | File | Job |
|---|---|---|
| Sigma rules | `rules/linux/*.yml` | detection logic + metadata (ATT&CK, level, false positives) |
| Processing pipeline | `pipelines/splunk/homelab.yml` | adds `index`/`sourcetype`; aborts on fields outside the schema |
| Conversion | `scripts/convert_rules.py` (`convert-rules.sh`) | official pySigma Splunk backend → `generated/` |
| Validation | `scripts/validate-rules.sh` | `sigma check --fail-on-issues` |
| Local tests | `tests/` (pytest) | metadata, conversion, drift of `generated/`, detection logic against fixtures |
| Live test | `scripts/splunk-live-test.py` | fixtures through Cribl → Splunk, executes the generated SPL for real |
| CI | `../.github/workflows/validate.yml` | validate, convert, drift check, pytest – no secrets, no deployment |
| Normalization | `../scripts/cribl-setup.py` | Cribl pipeline producing the schema (part of the homelab repo) |

## What is checked locally, what in Splunk

| Check | Where | Evidence |
|---|---|---|
| Sigma syntax, metadata, ATT&CK tags | local + CI | `validate-rules.sh`, `test_rule_metadata.py` |
| Convertible, correct index | local + CI | `test_rules_convert_to_spl_with_homelab_index` |
| `generated/` matches `rules/` | local + CI | `test_generated_files_are_up_to_date`, CI step `git status` |
| Detection logic positive/negative, correlation | local + CI | `test_detection_logic.py` – evaluates the condition tree parsed by pySigma, not the SPL |
| Generated SPL returns the expected hits in Splunk | Splunk only | `scripts/splunk-live-test.py` (manual, on the Docker VM) |

The local evaluator (`tests/sigma_eval.py`) supports only the Sigma constructs in use and raises
`NotImplementedError` for anything else instead of passing silently.
