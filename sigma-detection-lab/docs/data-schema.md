# Event-Schema (normalisiert)

[English version](data-schema.en.md)

Alle Regeln arbeiten ausschließlich auf diesen Feldern. Die Normalisierung passiert in der Cribl-Pipeline
`homelab_auth_normalize` ([`../../scripts/cribl-setup.py`](../../scripts/cribl-setup.py)); Splunk sieht jedes
Event als JSON in `index=homelab_auth sourcetype=homelab:auth` (Feldextraktion per `KV_MODE=json`).
Maschinenlesbare Fassung für die Tests: [`../tests/schema.py`](../tests/schema.py).
Die Processing-Pipeline [`../pipelines/splunk/homelab.yml`](../pipelines/splunk/homelab.yml) bricht die
Konvertierung ab, wenn eine Regel ein Feld außerhalb dieser Liste verwendet.

## Felder

| Feld | Typ | Bedeutung |
|---|---|---|
| `event_time` | ISO 8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` | Zeitpunkt des Ereignisses; Cribl setzt daraus `_time` |
| `event_type` | `authentication` \| `sudo` \| `user_created` \| `group_created` \| andere | Art des Ereignisses |
| `host` | String | Host, der das Log geschrieben hat (Splunk-Metadatum, nicht in `_raw`) |
| `user` | String | Handelnder Account (Login-Name, sudo-Aufrufer) |
| `target_user` | String | Ziel-Account (sudo `USER=`, neu angelegter Account) |
| `src` | IP-Adresse | Quelle der Anmeldung (nur `authentication`) |
| `dest` | String | Zielsystem; Standard = `host` |
| `action` | `success` \| `failure` | Ergebnis; andere Werte sind ungültig |
| `service` | String | Dienst: `ssh`, `sudo`, `useradd`, … |
| `command` | String | Von sudo autorisierte Kommandozeile |
| `environment` | String | Umgebung, Standard `homelab` |

## Pflichtfelder je `event_type`

Basis für alle Events: `event_time`, `event_type`, `host`, `dest`, `service`, `environment`.

| `event_type` | zusätzlich Pflicht | Quelle |
|---|---|---|
| `authentication` | `user`, `src`, `action` | sshd |
| `sudo` | `user`, `target_user`, `action`, `command` | sudo |
| `user_created` | `target_user`, `action` | useradd (`new user:`) |
| `group_created` | `target_user`, `action` | useradd (`new group:`) |
| andere (z. B. `cron`) | – | wird nicht weitergeleitet bzw. von keiner Regel ausgewertet |

`action` ist nur gesetzt, wo die Quelle Erfolg und Misserfolg zuverlässig unterscheidet: sshd
(`Accepted`/`Failed`/`Invalid user`) und sudo (Fehlertext vor `PWD=`). useradd schreibt nur bei Erfolg.

## Native Linux-Logs → Schema

Die Zeilen unten stammen aus `/var/log/auth.log` der Lab-VM (Ubuntu, rsyslog → Cribl Syslog UDP 9514);
IP-Adressen durch Dokumentationsadressen ersetzt.

### sshd

```
Oct 15 17:18:01 lab-linux-01 sshd[1234]: Invalid user mallory from 203.0.113.10 port 50022
```

| Originalfeld (Cribl Syslog-Input) | Extraktion | Normalisiert |
|---|---|---|
| `appname=sshd` | – | `service=ssh`, `event_type=authentication` |
| `message` | Regex `^(?<action>Accepted\|Failed\|Invalid user)\s+(?:\S+ for\s+)?(?:invalid user\s+)?(?<user>\S+) from (?<src>\S+)` | `user=mallory`, `src=203.0.113.10` |
| `action=Invalid user` | Mapping `failed/denied/error/invalid user → failure`, `accepted/ok/succeeded → success` | `action=failure` |
| `host=lab-linux-01` | – | `host`, `dest=lab-linux-01` |
| Syslog-Zeitstempel → `_time` | – | `event_time` |

### sudo

```
Oct 15 18:15:57 lab-linux-01 sudo:  labsudo : PWD=/home/labsudo ; USER=root ; COMMAND=/usr/bin/cat /etc/hostname
```

| Original | Extraktion | Normalisiert |
|---|---|---|
| `appname=sudo` | – | `service=sudo`, `event_type=sudo` |
| `message` | Regex `^\s*(?<user>\S+) : (?:(?<sudo_error>[^;=]+?) ; )?(?:TTY=\S+ ; )?PWD=\S+ ; USER=(?<target_user>\S+) ; COMMAND=(?<command>.+)$` | `user=labsudo`, `target_user=root`, `command=/usr/bin/cat /etc/hostname` |
| `sudo_error` (z. B. `3 incorrect password attempts`, `command not allowed`) | vorhanden → `failure`, sonst `success` | `action=success` |

`TTY=` fehlt bei Aufrufen ohne Terminal; die Regex akzeptiert beides.

### useradd

```
Oct 15 18:15:57 lab-linux-01 useradd[16999]: new group: name=labsudo, GID=1000
Oct 15 18:15:57 lab-linux-01 useradd[16999]: new user: name=labsudo, UID=1000, GID=1000, home=/home/labsudo, shell=/bin/bash, from=none
```

| Original | Extraktion | Normalisiert |
|---|---|---|
| `appname=useradd` | – | `service=useradd`, `action=success` |
| `message` | Regex `^new (?<useradd_kind>user\|group): name=(?<target_user>[^,]+)` | `target_user=labsudo` |
| `useradd_kind` | `user → user_created`, `group → group_created` | `event_type` |

Nur Syslog-Zeilen dieser drei Formen passieren die Cribl-Route `homelab_auth`; alle anderen
(z. B. `pam_unix(sudo:session)`) werden nicht an Splunk weitergeleitet.

## Testdaten

[`../tests/fixtures/auth-events.jsonl`](../tests/fixtures/auth-events.jsonl): eine Zeile pro Testfall,
`{"id", "expect": [Regelnamen], "event": {…normalisiert…}}`, optional `"invalid": "<Grund>"` für bewusst
unvollständige/ungültige Events und `"live": false` für Events, die Cribl beim Live-Test verändern würde.
Nur erfundene Benutzer und Adressen aus den Dokumentationsnetzen (RFC 5737: `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`).
