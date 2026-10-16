"""Local: rule logic against synthetic events via tests/sigma_eval.py (no Splunk).

The expectations live in tests/fixtures/auth-events.jsonl ("expect"); the match results are computed by
evaluating each rule's parsed Sigma condition. Running the generated SPL in a real Splunk is a separate,
manual step: scripts/splunk-live-test.py.
"""
import json
import random

import pytest
from conftest import ROOT
from schema import problems
from sigma.collection import SigmaCollection
from sigma_eval import correlate, matches

# Shared with scripts/splunk-live-test.py
EXPECTED_CORRELATIONS = {
    name: {tuple(g) for g in spec["groups"]}
    for name, spec in json.loads((ROOT / "tests/fixtures/expected-correlations.json").read_text()).items()}


def detection_rules(rules):
    return {n: r for n, r in rules.items() if hasattr(r, "detection")}


def evaluate(rules, fixtures):
    return {f["id"]: sorted(n for n, r in detection_rules(rules).items() if matches(r, f["event"]))
            for f in fixtures}


def test_fixtures_cover_positive_and_negative_cases(fixtures):
    assert any(f["expect"] for f in fixtures) and any(not f["expect"] for f in fixtures)
    assert len({f["id"] for f in fixtures}) == len(fixtures), "fixture ids must be unique"


def test_fixture_schema_violations_are_exactly_the_marked_ones(fixtures):
    """Invalid/incomplete events are deliberate; the schema check must flag those and only those."""
    for f in fixtures:
        assert bool(problems(f["event"])) == ("invalid" in f), (f["id"], problems(f["event"]))


@pytest.mark.parametrize("case", ["positive", "negative"])
def test_detections(rules, fixtures, case):
    results = evaluate(rules, fixtures)
    selected = [f for f in fixtures if bool(f["expect"]) == (case == "positive")]
    assert selected
    for f in selected:
        assert results[f["id"]] == sorted(f["expect"]), f["id"]


def test_correlation(rules, fixtures):
    events = [f["event"] for f in fixtures]
    for name, expected in EXPECTED_CORRELATIONS.items():
        assert correlate(rules[name], events) == expected


def test_results_are_reproducible(rules, fixtures):
    """Same input -> same result, independent of run and event order."""
    shuffled = fixtures[:]
    random.Random(1).shuffle(shuffled)
    assert evaluate(rules, fixtures) == evaluate(rules, fixtures) == evaluate(rules, shuffled)
    events = [f["event"] for f in fixtures]
    assert correlate(rules["ssh_password_guessing"], events) == correlate(
        rules["ssh_password_guessing"], list(reversed(events)))


def test_evaluator_refuses_unsupported_constructs():
    """A rule the evaluator cannot interpret must fail loudly, never pass silently."""
    (rule,) = SigmaCollection.from_yaml("""
title: Regex rule
logsource: {product: linux}
detection: {selection: {command|re: '.*shadow'}, condition: selection}
""").rules
    with pytest.raises(NotImplementedError):
        matches(rule, {"command": "cat /etc/shadow"})
