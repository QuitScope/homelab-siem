# Detection-Katalog

[English version](detection-catalog.en.md)

Quelle der Wahrheit sind die Sigma-Regeln in [`../rules/linux`](../rules/linux); die SPL in
[`../generated/spl`](../generated/spl) wird daraus erzeugt. Alle Regeln lesen `index=homelab_auth
sourcetype=homelab:auth` (konfigurierbar in [`../pipelines/splunk/homelab.yml`](../pipelines/splunk/homelab.yml)).

## A1 – SSH Authentication Failure

| | |
|---|---|
| Regel | `ssh_auth_failure` · `0fa37bd4-0eca-4626-833f-d18a6e181d33` · [ssh_auth_failure.yml](../rules/linux/ssh_auth_failure.yml) |
| Zweck | Einzelne fehlgeschlagene SSH-Anmeldung; Baustein für A2 |
| Datenquelle | sshd über rsyslog → Cribl (Syslog UDP 9514) |
| Felder | `event_type=authentication`, `service=ssh`, `action=failure`; Ausgabe `user`, `src`, `dest` |
| Schweregrad | low |
| ATT&CK | Credential Access – T1110.001 Password Guessing |
| Positiv | `ssh-fail-burst-1..3`, `ssh-fail-spread-1..2` |
| Negativ | `ssh-success`, `ftp-fail` (anderer Dienst), `ssh-fail-not-normalized` (`action=FAILED`), `ssh-fail-missing-action` |
| False Positives | vertippte Passwörter, Automatisierung mit veralteten Zugangsdaten |
| Grenzen | Ein einzelner Fehlversuch ist kein Angriff; ohne normalisiertes `action` keine Erkennung |

## A2 – SSH Password Guessing From Single Source (Korrelation)

| | |
|---|---|
| Regel | `ssh_password_guessing` · `e967f401-4764-4e38-8993-5dcb7730ce59` · gleiche Datei wie A1 |
| Zweck | ≥ 3 Fehlversuche derselben `src` in 5 Minuten (ersetzt seit 15.10.2026 den früheren Alert „HomeLab - Repeated Failed Logins“, der jetzt ungeplant ist) |
| Datenquelle / Felder | wie A1, Gruppierung nach `src` |
| Schweregrad | medium |
| ATT&CK | Credential Access – T1110.001 Password Guessing |
| Positiv | `203.0.113.10` (3 Fehler 10:00–10:02) |
| Negativ | `198.51.100.7` (2 Fehler im Abstand von 10 Minuten) |
| False Positives | Nutzer probiert mehrfach ein vergessenes Passwort; Schwachstellenscanner |
| Grenzen | Die erzeugte SPL nutzt feste 5-Minuten-Fenster (`bin _time span=5m`): 3 Fehler über eine Fenstergrenze verteilt werden nicht erkannt. Verteilte Angriffe (viele Quellen) und Password Spraying werden nicht erkannt |

## B – Sudo Command On Credential Or Sudoers Files

| | |
|---|---|
| Regel | `privileged_command` · `652b9997-f46f-44f2-8432-3ca55555b1d2` · [privileged_command.yml](../rules/linux/privileged_command.yml) |
| Zweck | Erfolgreich per sudo autorisiertes Kommando, das `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*` oder `visudo` referenziert |
| Datenquelle | sudo-Syslog-Zeile (`… USER=… ; COMMAND=…`) → Cribl |
| Felder | `event_type=sudo`, `action=success`, `command` (enthält); Ausgabe `user`, `target_user`, `command`, `dest` |
| Schweregrad | high |
| ATT&CK | Credential Access – T1003.008 /etc/passwd and /etc/shadow; Privilege Escalation – T1548.003 Sudo and Sudo Caching |
| Positiv | `sudo-read-shadow`, `sudo-append-sudoers-d`, `sudo-visudo` |
| Negativ | `sudo-benign-apt`, `sudo-read-passwd` (weltlesbar), `sudo-denied-shadow` (abgelehnt), `sudo-missing-command` |
| False Positives | Admins, die sudoers bewusst mit `visudo` bearbeiten; Konfigurationsmanagement |
| Grenzen | sudo protokolliert das autorisierte Kommando, nicht dessen Wirkung. Kommandos in einer Root-Shell (`sudo -s`, `sudo -i`) und Umgehungen ohne die Pfade in der Kommandozeile (`cd /etc; cat shadow`, Variablen) sind unsichtbar – dafür sind sudo I/O-Logging oder auditd-`execve`/Datei-Watches nötig. Abgelehnte Versuche erkennt die Regel bewusst nicht |

## C – Local User Account Created

| | |
|---|---|
| Regel | `user_account_created` · `748c936b-218c-4115-a669-1107560a75b2` · [user_account_created.yml](../rules/linux/user_account_created.yml) |
| Zweck | Neues lokales Benutzerkonto |
| Datenquelle | useradd-Syslog-Zeile `new user: name=…` (auch bei `adduser`) → Cribl |
| Felder | `event_type=user_created`; Ausgabe `target_user`, `dest` |
| Schweregrad | medium |
| ATT&CK | Persistence – T1136.001 Local Account |
| Positiv | `user-created`, `user-created-missing-name` (Konto ohne Namen – wird trotzdem gemeldet) |
| Negativ | `group-created` (gleicher useradd-Aufruf), `irrelevant-cron` |
| False Positives | geplantes Onboarding; Pakete, die Dienstkonten anlegen |
| Grenzen | Direkte Bearbeitung von `/etc/passwd` oder Werkzeuge ohne useradd werden nicht erkannt (auditd-Watch nötig). Der ausführende Benutzer steht nicht in der useradd-Zeile |
