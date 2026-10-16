"""Local: YAML syntax, Sigma metadata, ATT&CK consistency, Splunk conversion and generated-file drift."""
import re
import uuid

import pytest
import yaml
from conftest import ROOT
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.processing.pipeline import ProcessingPipeline

RULE_FILES = sorted((ROOT / "rules").rglob("*.yml"))
DOCS = [d for f in RULE_FILES for d in yaml.safe_load_all(f.read_text(encoding="utf-8"))]
COMMON = {"title", "id", "name", "status", "description", "author", "date", "references", "tags",
          "falsepositives", "level"}
TECHNIQUE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$")


def test_rule_files_exist():
    assert len(RULE_FILES) >= 3


@pytest.mark.parametrize("doc", DOCS, ids=lambda d: d["name"])
def test_required_metadata(doc):
    required = COMMON | ({"correlation"} if "correlation" in doc else {"logsource", "detection"})
    assert not required - set(doc), f"missing keys: {required - set(doc)}"
    assert doc["level"] in {"informational", "low", "medium", "high", "critical"}
    assert doc["falsepositives"], "false-positive notes must not be empty"
    assert len(doc["description"].split()) >= 10, "description too short"
    uuid.UUID(doc["id"])


@pytest.mark.parametrize("doc", DOCS, ids=lambda d: d["name"])
def test_attack_tags_match_references(doc):
    techniques = [TECHNIQUE.match(t) for t in doc["tags"] if TECHNIQUE.match(t)]
    assert techniques, "at least one ATT&CK technique tag"
    for m in techniques:
        url = f"https://attack.mitre.org/techniques/T{m[1]}/" + (f"{m[2]}/" if m[2] else "")
        assert url in doc["references"], f"tag {m[0]} needs reference {url}"


def test_ids_and_names_unique():
    for key in ("id", "name"):
        values = [d[key] for d in DOCS]
        assert len(values) == len(set(values)), f"duplicate {key}"


def test_every_rule_has_positive_and_negative_fixture(rules, fixtures):
    """Negative = a non-matching event from the same source (service) as the positives, not just any event."""
    for name, rule in rules.items():
        if not hasattr(rule, "detection"):
            continue  # correlations: covered by test_detection_logic.test_correlation
        positives = [f for f in fixtures if name in f["expect"]]
        services = {f["event"]["service"] for f in positives}
        negatives = [f for f in fixtures if name not in f["expect"] and f["event"]["service"] in services]
        assert positives and negatives, f"{name}: needs >=1 positive and >=1 same-source negative fixture"


def test_rules_convert_to_spl_with_homelab_index():
    from convert_rules import convert_all
    queries = {k: v for k, v in convert_all().items() if k.endswith(".spl")}
    assert len(queries) == len(DOCS)
    for path, spl in queries.items():
        assert spl.startswith('index="homelab_auth" sourcetype="homelab:auth" '), path


def test_generated_files_are_up_to_date():
    """generated/ must be reproducible from rules/; fails if someone edited it by hand or forgot to convert."""
    from convert_rules import convert_all
    for rel, content in convert_all().items():
        assert (ROOT / rel).read_text(encoding="utf-8") == content, f"{rel} is stale, run scripts/convert-rules.sh"
    committed = {p.relative_to(ROOT).as_posix() for p in (ROOT / "generated" / "spl").glob("*.spl")}
    assert committed == {k for k in convert_all() if k.endswith(".spl")}, "orphaned files in generated/spl"


def test_pipeline_rejects_fields_outside_schema():
    rule = SigmaCollection.from_yaml("""
title: Uses a non-schema field
logsource: {product: linux, service: sshd}
detection: {selection: {SourceIp: 203.0.113.10}, condition: selection}
""")
    pipeline = ProcessingPipeline.from_yaml((ROOT / "pipelines/splunk/homelab.yml").read_text(encoding="utf-8"))
    with pytest.raises(SigmaTransformationError, match="not part of the normalized HomeLab schema"):
        SplunkBackend(pipeline).convert(rule)
