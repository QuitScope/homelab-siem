# Detection catalog

[Deutsche Version](detection-catalog.md)

The Sigma rules in [`../rules/linux`](../rules/linux) are the source of truth; the SPL in
[`../generated/spl`](../generated/spl) is generated from them. All rules read `index=homelab_auth
sourcetype=homelab:auth` (configurable in [`../pipelines/splunk/homelab.yml`](../pipelines/splunk/homelab.yml)).

## A1 – SSH Authentication Failure

| | |
|---|---|
| Rule | `ssh_auth_failure` · `0fa37bd4-0eca-4626-833f-d18a6e181d33` · [ssh_auth_failure.yml](../rules/linux/ssh_auth_failure.yml) |
| Purpose | single failed SSH login; building block for A2 |
| Data source | sshd via rsyslog → Cribl (syslog UDP 9514) |
| Fields | `event_type=authentication`, `service=ssh`, `action=failure`; output `user`, `src`, `dest` |
| Level | low |
| ATT&CK | Credential Access – T1110.001 Password Guessing |
| Positive | `ssh-fail-burst-1..3`, `ssh-fail-spread-1..2` |
| Negative | `ssh-success`, `ftp-fail` (other service), `ssh-fail-not-normalized` (`action=FAILED`), `ssh-fail-missing-action` |
| False positives | mistyped passwords, automation with outdated credentials |
| Limits | one failure is not an attack; no detection without a normalized `action` |

## A2 – SSH Password Guessing From Single Source (correlation)

| | |
|---|---|
| Rule | `ssh_password_guessing` · `e967f401-4764-4e38-8993-5dcb7730ce59` · same file as A1 |
| Purpose | ≥ 3 failures from the same `src` within 5 minutes (since 2026-10-15 replaces the former alert "HomeLab - Repeated Failed Logins", now unscheduled) |
| Data source / fields | as A1, grouped by `src` |
| Level | medium |
| ATT&CK | Credential Access – T1110.001 Password Guessing |
| Positive | `203.0.113.10` (3 failures 10:00–10:02) |
| Negative | `198.51.100.7` (2 failures 10 minutes apart) |
| False positives | a user retrying a forgotten password; vulnerability scanners |
| Limits | the generated SPL uses fixed 5-minute buckets (`bin _time span=5m`): 3 failures spread across a bucket boundary are missed. Distributed attacks (many sources) and password spraying are not detected |

## B – Sudo Command On Credential Or Sudoers Files

| | |
|---|---|
| Rule | `privileged_command` · `652b9997-f46f-44f2-8432-3ca55555b1d2` · [privileged_command.yml](../rules/linux/privileged_command.yml) |
| Purpose | a command successfully authorized by sudo that references `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*` or `visudo` |
| Data source | sudo syslog line (`… USER=… ; COMMAND=…`) → Cribl |
| Fields | `event_type=sudo`, `action=success`, `command` (contains); output `user`, `target_user`, `command`, `dest` |
| Level | high |
| ATT&CK | Credential Access – T1003.008 /etc/passwd and /etc/shadow; Privilege Escalation – T1548.003 Sudo and Sudo Caching |
| Positive | `sudo-read-shadow`, `sudo-append-sudoers-d`, `sudo-visudo` |
| Negative | `sudo-benign-apt`, `sudo-read-passwd` (world-readable), `sudo-denied-shadow` (denied), `sudo-missing-command` |
| False positives | admins deliberately editing sudoers with `visudo`; configuration management |
| Limits | sudo logs the authorized command, not its effect. Commands inside a root shell (`sudo -s`, `sudo -i`) and evasions without the path in the command line (`cd /etc; cat shadow`, variables) are invisible – that needs sudo I/O logging or auditd `execve`/file watches. Denied attempts are deliberately not matched |

## C – Local User Account Created

| | |
|---|---|
| Rule | `user_account_created` · `748c936b-218c-4115-a669-1107560a75b2` · [user_account_created.yml](../rules/linux/user_account_created.yml) |
| Purpose | new local user account |
| Data source | useradd syslog line `new user: name=…` (also for `adduser`) → Cribl |
| Fields | `event_type=user_created`; output `target_user`, `dest` |
| Level | medium |
| ATT&CK | Persistence – T1136.001 Local Account |
| Positive | `user-created`, `user-created-missing-name` (account without name – still reported) |
| Negative | `group-created` (same useradd call), `irrelevant-cron` |
| False positives | planned onboarding; packages creating service accounts |
| Limits | editing `/etc/passwd` directly or tools that bypass useradd are not detected (needs an auditd watch). The useradd line does not contain the acting user |
