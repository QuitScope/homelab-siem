"""Minimal local evaluator for Sigma rules against normalized JSON events (no Splunk needed).

It walks the condition tree that pySigma parses from the rule itself, so the tests exercise the real rule
logic. Only the constructs used in rules/ are supported; anything else raises NotImplementedError instead of
silently passing. Semantics follow Splunk: field values match case-insensitively, `*` is a wildcard, a
missing field never matches. Correlations (event_count) use fixed time buckets like the generated SPL
(`bin _time span=...`).
"""
import re
from collections import Counter
from datetime import datetime, timezone

from sigma.collection import SigmaCollection
from sigma.conditions import (ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR,
                              ConditionValueExpression)
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule, SigmaCorrelationType
from sigma.rule import SigmaRule
from sigma.types import SigmaNull, SigmaNumber, SigmaString, SpecialChars

OPS = {SigmaCorrelationConditionOperator.GTE: int.__ge__, SigmaCorrelationConditionOperator.GT: int.__gt__,
       SigmaCorrelationConditionOperator.LTE: int.__le__, SigmaCorrelationConditionOperator.LT: int.__lt__,
       SigmaCorrelationConditionOperator.EQ: int.__eq__}


def load_rules(path) -> dict:
    """{rule name: SigmaRule | SigmaCorrelationRule}, parsed without any processing pipeline."""
    return {r.name: r for r in SigmaCollection.load_ruleset([str(path)]).rules}


def _value_matches(value, actual) -> bool:
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(value, SigmaNumber):
        return str(value.number) == str(actual)
    if isinstance(value, SigmaString):
        pattern = "".join(re.escape(p) if isinstance(p, str)
                          else {SpecialChars.WILDCARD_MULTI: ".*", SpecialChars.WILDCARD_SINGLE: "."}[p]
                          for p in value.s)
        return re.fullmatch(pattern, str(actual), re.IGNORECASE | re.DOTALL) is not None
    raise NotImplementedError(f"value type {type(value).__name__} not supported by the local evaluator")


def _eval(node, event) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _value_matches(node.value, event.get(node.field))
    if isinstance(node, ConditionValueExpression):
        raise NotImplementedError("keyword (field-less) search not supported by the local evaluator")
    raise NotImplementedError(f"condition {type(node).__name__} not supported by the local evaluator")


def matches(rule: SigmaRule, event: dict) -> bool:
    return any(_eval(c.parsed, event) for c in rule.detection.parsed_condition)


def correlate(corr: SigmaCorrelationRule, events: list[dict]) -> set[tuple]:
    """Returns the group-by value tuples for which the correlation fires."""
    if corr.type != SigmaCorrelationType.EVENT_COUNT or corr.condition.fieldref:
        raise NotImplementedError(f"correlation type {corr.type} not supported by the local evaluator")
    span = corr.timespan.seconds
    counts = Counter()
    for e in events:
        if any(matches(ref.rule, e) for ref in corr.rules):
            ts = datetime.strptime(e["event_time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            bucket = int(ts.timestamp()) // span
            counts[(bucket, tuple(e.get(f) for f in corr.group_by))] += 1
    op = OPS[corr.condition.op]
    return {group for (_, group), n in counts.items() if op(n, corr.condition.count)}
