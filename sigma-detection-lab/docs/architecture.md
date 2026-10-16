# Architektur

[English version](architecture.en.md)

```
 Datenpfad (Homelab, besteht bereits)                    Detection-as-Code (dieses Projekt)
 ─────────────────────────────────────                   ──────────────────────────────────
 lab-linux-01                                            rules/linux/*.yml   (Sigma, Quelle der Wahrheit)
   sshd / sudo / useradd → /var/log/auth.log                    │
   rsyslog  auth,authpriv.* → UDP 9514                          │ pySigma + Splunk-Backend
        │                                                       │ + pipelines/splunk/homelab.yml
        ▼                                                       ▼   (Index, Sourcetype, Schema-Guard)
 Cribl Stream (siem-docker)                              generated/spl/*.spl
   Route homelab_auth                                    generated/savedsearches.conf
   Pipeline homelab_auth_normalize:                             │
     sshd/sudo/useradd parsen → Schema-Felder                   │ manueller Import (siehe README)
     → JSON _raw                                                ▼
        │  HEC (nur Docker-Netz)                         Splunk: Saved Searches / Alerts
        ▼                                                  auf index=homelab_auth
 Splunk Enterprise  index=homelab_auth  sourcetype=homelab:auth  ◀──────┘
```

## Komponenten

| Teil | Datei | Aufgabe |
|---|---|---|
| Sigma-Regeln | `rules/linux/*.yml` | Detection-Logik + Metadaten (ATT&CK, Level, False Positives) |
| Processing-Pipeline | `pipelines/splunk/homelab.yml` | ergänzt `index`/`sourcetype`; bricht ab bei Feldern außerhalb des Schemas |
| Konvertierung | `scripts/convert_rules.py` (`convert-rules.sh`) | offizielles pySigma-Splunk-Backend → `generated/` |
| Validierung | `scripts/validate-rules.sh` | `sigma check --fail-on-issues` |
| Lokale Tests | `tests/` (pytest) | Metadaten, Konvertierung, Drift von `generated/`, Detection-Logik gegen Fixtures |
| Live-Test | `scripts/splunk-live-test.py` | Fixtures durch Cribl → Splunk, generierte SPL echt ausführen |
| CI | `../.github/workflows/validate.yml` | validieren, konvertieren, Drift prüfen, pytest – keine Secrets, kein Deployment |
| Normalisierung | `../scripts/cribl-setup.py` | Cribl-Pipeline, die das Schema erzeugt (Teil des Homelab-Repos) |

## Was lokal, was in Splunk geprüft wird

| Prüfung | Wo | Nachweis |
|---|---|---|
| Sigma-Syntax, Metadaten, ATT&CK-Tags | lokal + CI | `validate-rules.sh`, `test_rule_metadata.py` |
| Konvertierbarkeit, richtiger Index | lokal + CI | `test_rules_convert_to_spl_with_homelab_index` |
| `generated/` passt zu `rules/` | lokal + CI | `test_generated_files_are_up_to_date`, CI-Schritt `git status` |
| Detection-Logik positiv/negativ, Korrelation | lokal + CI | `test_detection_logic.py` – wertet den von pySigma geparsten Bedingungsbaum aus, nicht die SPL |
| Generierte SPL liefert in Splunk die erwarteten Treffer | nur Splunk | `scripts/splunk-live-test.py` (manuell, auf der Docker-VM) |

Der lokale Evaluator (`tests/sigma_eval.py`) unterstützt nur die verwendeten Sigma-Konstrukte und bricht bei
allem anderen mit `NotImplementedError` ab, statt still zu bestehen.
