# MITRE ATT&CK coverage

[Deutsche Version](mitre-coverage.md)

Mappings checked on 2026-10-15 against the official technique pages (links). Rule tags follow the Sigma
convention (`attack.<tactic>`, `attack.t<id>`); `sigma check` validates them and
`tests/test_rule_metadata.py` enforces a matching reference link for every technique tag.

| Tactic | Technique | Rule | Rationale |
|---|---|---|---|
| Credential Access (TA0006) | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | A1 `ssh_auth_failure`, A2 `ssh_password_guessing` | the page names SSH (22/TCP) as a target and repeated failed SSH logins as a detection approach. A1 alone is only a weak indicator (low) |
| Credential Access (TA0006) | [T1003.008 /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/) | B `privileged_command` | reading `/etc/shadow` (root-only) to crack the hashes offline |
| Privilege Escalation (TA0004) | [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | B `privileged_command` | the page describes changes to `/etc/sudoers` and `/etc/sudoers.d/` (e.g. NOPASSWD) |
| Persistence (TA0003) | [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) | C `user_account_created` | the page names `useradd` as the Linux way to create local accounts |

Deliberately not mapped: generic Brute Force (T1110) without sub-technique, Password Spraying (T1110.003) –
that would need a correlation across many users, which is not implemented.
