# MITRE-ATT&CK-Abdeckung

[English version](mitre-coverage.en.md)

Zuordnungen geprüft am 15.10.2026 gegen die offiziellen Technikseiten (Links). Die Tags in den Regeln
folgen der Sigma-Konvention (`attack.<taktik>`, `attack.t<id>`); `sigma check` validiert sie, und
`tests/test_rule_metadata.py` erzwingt zu jedem Technik-Tag den passenden Referenz-Link.

| Taktik | Technik | Regel | Begründung |
|---|---|---|---|
| Credential Access (TA0006) | [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | A1 `ssh_auth_failure`, A2 `ssh_password_guessing` | Seite nennt SSH (22/TCP) als Ziel und wiederholte fehlgeschlagene SSH-Logins als Erkennungsansatz. A1 allein ist nur ein schwacher Indikator (low) |
| Credential Access (TA0006) | [T1003.008 /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008/) | B `privileged_command` | Lesen von `/etc/shadow` (nur für root lesbar) zum Offline-Knacken der Hashes |
| Privilege Escalation (TA0004) | [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) | B `privileged_command` | Seite beschreibt Änderungen an `/etc/sudoers` und `/etc/sudoers.d/` (z. B. NOPASSWD) |
| Persistence (TA0003) | [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) | C `user_account_created` | Seite nennt `useradd` als Linux-Weg zum Anlegen lokaler Konten |

Bewusst nicht zugeordnet: Brute Force allgemein (T1110) ohne Untertechnik, Password Spraying (T1110.003) –
dafür bräuchte es eine Korrelation über viele Benutzer, die nicht implementiert ist.
