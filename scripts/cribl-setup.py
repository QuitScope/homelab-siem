#!/usr/bin/env python3
"""Configures Cribl Stream via REST API: HTTP source -> homelab_auth_normalize -> Splunk HEC.

Idempotent (create or update). Run on the Docker VM:
  set -a; . ./.env; set +a; python3 scripts/cribl-setup.py
Env: SPLUNK_HEC_TOKEN (required), CRIBL_URL, CRIBL_USER, CRIBL_PASSWORD
"""
import json
import os
import urllib.error
import urllib.request

URL = os.environ.get("CRIBL_URL", "http://localhost:9000") + "/api/v1"
HEC_TOKEN = os.environ["SPLUNK_HEC_TOKEN"]


def call(method, path, body=None, token=None):
    req = urllib.request.Request(URL + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path}: {e.code} {e.read().decode()[:300]}")


def upsert(token, path, obj):
    # Cribl answers PATCH on a missing id with 500, not 404, so check the list first
    exists = any(i["id"] == obj["id"] for i in call("GET", path, token=token)["items"])
    call("PATCH" if exists else "POST", f"{path}/{obj['id']}" if exists else path, obj, token)
    print("ok", path, obj["id"])


ACTION_MAP = ("({failed:'failure',failure:'failure',fail:'failure',denied:'failure',error:'failure',"
              "invalid:'failure','invalid user':'failure',success:'success',succeeded:'success',"
              "accepted:'success',ok:'success'})[String(action).toLowerCase()] || 'unknown'")

# sshd syslog lines: "Failed password for [invalid user] X from IP", "Accepted publickey for X from IP",
# "Invalid user X from IP"
SSHD_REGEX = r"/^(?<action>Accepted|Failed|Invalid user)\s+(?:\S+ for\s+)?(?:invalid user\s+)?(?<user>\S+) from (?<src>\S+)/"
# sudo: "alice : [3 incorrect password attempts ; ][TTY=pts/0 ; ]PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
SUDO_REGEX = (r"/^\s*(?<user>\S+) : (?:(?<sudo_error>[^;=]+?) ; )?(?:TTY=\S+ ; )?PWD=\S+ ; "
              r"USER=(?<target_user>\S+) ; COMMAND=(?<command>.+)$/")
# useradd: "new user: name=bob, UID=1001, ..." / "new group: name=bob, GID=1001"
USERADD_REGEX = r"/^new (?<useradd_kind>user|group): name=(?<target_user>[^,]+)/"
SSHD_FILTER = ("__inputId.startsWith('syslog') && ("
               "(appname == 'sshd' && /^(Accepted|Failed|Invalid user) /.test(message))"
               " || (appname == 'sudo' && / COMMAND=/.test(message))"
               " || (appname == 'useradd' && /^new (user|group): /.test(message)))")
ACTION = (f"appname == 'sudo' ? (sudo_error ? 'failure' : 'success')"
          f" : appname == 'useradd' ? 'success' : {ACTION_MAP}")
EVENT_TYPE = ("event_type || (appname == 'sudo' ? 'sudo'"
              " : appname == 'useradd' ? (useradd_kind == 'user' ? 'user_created' : 'group_created')"
              " : 'authentication')")
# Only these reach Splunk; everything else (syslog metadata, debug fields) is dropped before HEC
KEEP = ["_raw", "_time", "index", "sourcetype", "source", "host"]

PIPELINE = {"id": "homelab_auth_normalize", "conf": {"asyncFuncTimeout": 1000, "functions": [
    # Debug noise is the only thing we drop; failed logins are never dropped.
    {"id": "drop", "filter": "String(level).toLowerCase() == 'debug'", "conf": {},
     "description": "Drop debug-only events"},
    {"id": "regex_extract", "filter": "appname == 'sshd'", "description": "Parse sshd auth lines",
     "conf": {"source": "message", "regex": SSHD_REGEX, "iterations": 100, "overwrite": False}},
    {"id": "regex_extract", "filter": "appname == 'sudo'", "description": "Parse sudo command lines",
     "conf": {"source": "message", "regex": SUDO_REGEX, "iterations": 100, "overwrite": False}},
    {"id": "regex_extract", "filter": "appname == 'useradd'", "description": "Parse useradd lines",
     "conf": {"source": "message", "regex": USERADD_REGEX, "iterations": 100, "overwrite": False}},
    {"id": "eval", "filter": "true", "description": "Normalize auth fields", "conf": {
        "add": [
            {"name": "_time", "value": "event_time ? Date.parse(event_time) / 1000 : _time"},
            {"name": "event_time", "value": "event_time || new Date(_time * 1000).toISOString()"},
            {"name": "user", "value": "user || username || user_name"},
            {"name": "src", "value": "src || src_ip || rhost"},
            {"name": "dest", "value": "dest || host"},
            {"name": "action", "value": ACTION},
            {"name": "event_type", "value": EVENT_TYPE},
            {"name": "service", "value": "service || (appname == 'sshd' ? 'ssh' : appname)"},
            {"name": "environment", "value": "environment || 'homelab'"},
        ]}},
    {"id": "eval", "filter": "true", "description": "Build JSON _raw + Splunk metadata", "conf": {
        "add": [
            # host stays Splunk metadata only; in _raw too, KV_MODE=json would make it multivalue
            # undefined fields (e.g. src for sudo) are omitted by JSON.stringify
            {"name": "_raw", "value": "JSON.stringify({event_time, event_type, user, target_user, src, dest,"
                                      " action, service, command, environment})"},
            {"name": "index", "value": "'homelab_auth'"},
            {"name": "sourcetype", "value": "'homelab:auth'"},
            {"name": "source", "value": "'cribl:' + __inputId"},
        ],
        "keep": KEEP, "remove": ["*"]}},
]}}

# Baseline for the data-reduction measurement: the same events, unchanged, as JSON
BASELINE = {"id": "homelab_auth_baseline", "conf": {"asyncFuncTimeout": 1000, "functions": [
    {"id": "eval", "filter": "true", "description": "Drop measurement marker", "conf": {"remove": ["measure", "cribl"]}},
    {"id": "serialize", "filter": "true", "description": "All original fields into _raw",
     "conf": {"type": "json", "fields": ["!_*", "!host", "!cribl*", "*"], "dstField": "_raw"}},
    {"id": "eval", "filter": "true", "description": "Splunk metadata", "conf": {
        "add": [{"name": "index", "value": "'homelab_baseline'"},
                {"name": "sourcetype", "value": "'homelab:raw'"},
                {"name": "source", "value": "'cribl:' + __inputId"}],
        "keep": KEEP, "remove": ["*"]}},
]}}


def route(id_, filter_, pipeline, final):
    return {"id": id_, "name": id_, "final": final, "disabled": False, "filter": filter_,
            "pipeline": pipeline, "output": "splunk_homelab", "enableOutputExpression": False,
            "clones": [], "description": ""}


ROUTES = [
    # non-final: a copy of every measurement event goes to the baseline, the original continues
    route("homelab_baseline", "__inputId.startsWith('http') && measure", "homelab_auth_baseline", False),
    route("homelab_auth", f"__inputId.startsWith('http') || ({SSHD_FILTER})", "homelab_auth_normalize", True),
]


def main():
    login = call("POST", "/auth/login", {"username": os.environ.get("CRIBL_USER", "admin"),
                                          "password": os.environ.get("CRIBL_PASSWORD", "admin")})
    t = login["token"]
    upsert(t, "/system/inputs", {"id": "http", "type": "http", "disabled": False,
                                 "host": "0.0.0.0", "port": 10080, "criblAPI": "/cribl",
                                 "splunkHecAPI": "/services/collector", "elasticAPI": "/elastic"})
    upsert(t, "/system/outputs", {"id": "splunk_homelab", "type": "splunk_hec",
                                  "url": "http://splunk:8088/services/collector/event",
                                  "authType": "manual", "token": HEC_TOKEN})
    upsert(t, "/system/inputs", {"id": "in_syslog", "type": "syslog", "disabled": False,
                                 "host": "0.0.0.0", "udpPort": 9514, "tcpPort": 9514,
                                 "timestampTimezone": "local", "tls": {"disabled": True}})
    upsert(t, "/pipelines", PIPELINE)
    upsert(t, "/pipelines", BASELINE)
    routes = call("GET", "/routes/default", token=t)["items"][0]
    ours = {r["id"] for r in ROUTES}
    routes["routes"] = ROUTES + [r for r in routes["routes"] if r["id"] not in ours]
    call("PATCH", "/routes/default", routes, t)
    print("ok routes", ", ".join(ours))


if __name__ == "__main__":
    main()
