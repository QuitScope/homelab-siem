# Event schema (normalized)

[Deutsche Version](data-schema.md)

All rules use only these fields. Normalization happens in the Cribl pipeline `homelab_auth_normalize`
([`../../scripts/cribl-setup.py`](../../scripts/cribl-setup.py)); Splunk sees every event as JSON in
`index=homelab_auth sourcetype=homelab:auth` (`KV_MODE=json`). Machine-readable version for the tests:
[`../tests/schema.py`](../tests/schema.py). The processing pipeline
[`../pipelines/splunk/homelab.yml`](../pipelines/splunk/homelab.yml) aborts conversion if a rule uses any other field.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `event_time` | ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` | time of the event; Cribl derives `_time` from it |
| `event_type` | `authentication` \| `sudo` \| `user_created` \| `group_created` \| other | kind of event |
| `host` | string | host that wrote the log (Splunk metadata, not in `_raw`) |
| `user` | string | acting account (login name, sudo caller) |
| `target_user` | string | target account (sudo `USER=`, newly created account) |
| `src` | IP address | source of the login (`authentication` only) |
| `dest` | string | target system; defaults to `host` |
| `action` | `success` \| `failure` | outcome; any other value is invalid |
| `service` | string | service: `ssh`, `sudo`, `useradd`, … |
| `command` | string | command line authorized by sudo |
| `environment` | string | environment, default `homelab` |

## Required fields per `event_type`

Base for all events: `event_time`, `event_type`, `host`, `dest`, `service`, `environment`.

| `event_type` | additionally required | source |
|---|---|---|
| `authentication` | `user`, `src`, `action` | sshd |
| `sudo` | `user`, `target_user`, `action`, `command` | sudo |
| `user_created` | `target_user`, `action` | useradd (`new user:`) |
| `group_created` | `target_user`, `action` | useradd (`new group:`) |
| other (e.g. `cron`) | – | not forwarded / not used by any rule |

`action` is only set where the source reliably distinguishes success and failure: sshd
(`Accepted`/`Failed`/`Invalid user`) and sudo (error text before `PWD=`). useradd only logs on success.

## Native Linux logs → schema

Lines taken from `/var/log/auth.log` of the lab VM (Ubuntu, rsyslog → Cribl syslog UDP 9514); IP addresses
replaced with documentation addresses.

### sshd

```
Oct 15 17:18:01 lab-linux-01 sshd[1234]: Invalid user mallory from 203.0.113.10 port 50022
```

| Original field (Cribl syslog input) | Extraction | Normalized |
|---|---|---|
| `appname=sshd` | – | `service=ssh`, `event_type=authentication` |
| `message` | regex `^(?<action>Accepted\|Failed\|Invalid user)\s+(?:\S+ for\s+)?(?:invalid user\s+)?(?<user>\S+) from (?<src>\S+)` | `user=mallory`, `src=203.0.113.10` |
| `action=Invalid user` | map `failed/denied/error/invalid user → failure`, `accepted/ok/succeeded → success` | `action=failure` |
| `host=lab-linux-01` | – | `host`, `dest=lab-linux-01` |
| syslog timestamp → `_time` | – | `event_time` |

### sudo

```
Oct 15 18:15:57 lab-linux-01 sudo:  labsudo : PWD=/home/labsudo ; USER=root ; COMMAND=/usr/bin/cat /etc/hostname
```

| Original | Extraction | Normalized |
|---|---|---|
| `appname=sudo` | – | `service=sudo`, `event_type=sudo` |
| `message` | regex `^\s*(?<user>\S+) : (?:(?<sudo_error>[^;=]+?) ; )?(?:TTY=\S+ ; )?PWD=\S+ ; USER=(?<target_user>\S+) ; COMMAND=(?<command>.+)$` | `user=labsudo`, `target_user=root`, `command=/usr/bin/cat /etc/hostname` |
| `sudo_error` (e.g. `3 incorrect password attempts`, `command not allowed`) | present → `failure`, else `success` | `action=success` |

`TTY=` is missing for calls without a terminal; the regex accepts both.

### useradd

```
Oct 15 18:15:57 lab-linux-01 useradd[16999]: new group: name=labsudo, GID=1000
Oct 15 18:15:57 lab-linux-01 useradd[16999]: new user: name=labsudo, UID=1000, GID=1000, home=/home/labsudo, shell=/bin/bash, from=none
```

| Original | Extraction | Normalized |
|---|---|---|
| `appname=useradd` | – | `service=useradd`, `action=success` |
| `message` | regex `^new (?<useradd_kind>user\|group): name=(?<target_user>[^,]+)` | `target_user=labsudo` |
| `useradd_kind` | `user → user_created`, `group → group_created` | `event_type` |

Only syslog lines of these three forms pass the Cribl route `homelab_auth`; everything else
(e.g. `pam_unix(sudo:session)`) is not forwarded to Splunk.

## Test data

[`../tests/fixtures/auth-events.jsonl`](../tests/fixtures/auth-events.jsonl): one line per test case,
`{"id", "expect": [rule names], "event": {…normalized…}}`, optionally `"invalid": "<reason>"` for deliberately
incomplete/invalid events and `"live": false` for events Cribl would change during the live test. Only made-up
users and addresses from the documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
