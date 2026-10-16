"""Normalized HomeLab event schema (human-readable version: docs/data-schema.md)."""
from datetime import datetime

FIELDS = {"event_time", "event_type", "host", "user", "target_user", "src", "dest", "action", "service",
          "command", "environment"}
ACTIONS = {"success", "failure"}
BASE_REQUIRED = {"event_time", "event_type", "host", "dest", "service", "environment"}
# Extra required fields per event_type; other event types (e.g. cron) only need the base fields.
REQUIRED = {
    "authentication": {"user", "src", "action"},
    "sudo": {"user", "target_user", "action", "command"},
    "user_created": {"target_user", "action"},
    "group_created": {"target_user", "action"},
}


def problems(event: dict) -> list[str]:
    """Returns schema violations of a normalized event; empty list = valid."""
    found = [f"unknown field {f}" for f in sorted(set(event) - FIELDS)]
    missing = BASE_REQUIRED | REQUIRED.get(event.get("event_type"), set())
    found += [f"missing field {f}" for f in sorted(missing - set(event))]
    if "action" in event and event["action"] not in ACTIONS:
        found.append(f"invalid action {event['action']!r}")
    try:
        datetime.strptime(event.get("event_time", ""), "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        found.append(f"invalid event_time {event.get('event_time')!r}")
    return found
