#!/usr/bin/env python3
"""Data-reduction measurement: identical events through the unchanged (baseline) and the optimized pipeline.

Cribl clones every event marked `measure` to index homelab_baseline (unchanged JSON) while the original
goes through homelab_auth_normalize to homelab_auth. Both are counted in Splunk with sum(len(_raw)).
Run on the Docker VM:  set -a; . ./.env; set +a; python3 scripts/reduction-test.py [events=1000]
"""
import json
import random
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
CRIBL = "http://localhost:10080/cribl/_bulk"
RUN = "lab-reduce-" + datetime.now(timezone.utc).strftime("%H%M%S")


def dataset(n, rnd=random.Random(42)):
    """Typical agent output: auth events padded with agent metadata, plus debug heartbeats."""
    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
    for i in range(n):
        ts = (t0 + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        meta = {"measure": True, "host": RUN, "event_time": ts, "pid": rnd.randint(1000, 65000),
                "agent": {"name": "lab-agent", "version": "2.4.1", "uuid": f"{rnd.getrandbits(128):032x}"},
                "session_id": f"{rnd.getrandbits(64):016x}", "labels": ["homelab", "linux", "ssh"]}
        if rnd.random() < 0.25:
            yield {**meta, "level": "debug", "message": "sshd heartbeat: connection table ok",
                   "debug_trace": "poll=1 fds=12 " * 8}
            continue
        user, src = rnd.choice([("alice", "192.0.2.10"), ("bob", "192.0.2.20"), ("carol", "192.0.2.30")])
        action = rnd.choice(["Accepted", "Accepted", "Failed", "failed", "denied"])
        yield {**meta, "level": "info", "username": user, "src_ip": src, "action": action, "service": "ssh",
               "message": f"{action} password for {user} from {src} port {rnd.randint(30000, 60000)} ssh2",
               "debug_trace": f"auth.c:{rnd.randint(100, 999)} kex=curve25519 cipher=chacha20"}


def splunk(search):
    q = urllib.parse.urlencode({"search": "search " + search, "output_mode": "json", "earliest_time": "-2h"})
    out = subprocess.run(["docker", "exec", "homelab-siem-splunk-1", "sh", "-c",
                          'curl -sk -u "admin:$SPLUNK_PASSWORD" https://localhost:8089/services/search/jobs/export -d "$0"', q],
                         capture_output=True, text=True, check=True).stdout
    return [json.loads(line)["result"] for line in out.splitlines() if '"result"' in line]


def main():
    body = "".join(json.dumps(e) + "\n" for e in dataset(N)).encode()
    urllib.request.urlopen(urllib.request.Request(CRIBL, data=body, method="POST")).read()
    print(f"sent {N} events ({len(body)} bytes) as host={RUN}; waiting for indexing ...")
    rows = {}
    for _ in range(30):
        time.sleep(5)
        res = splunk(f"index=homelab_baseline OR index=homelab_auth host={RUN} "
                     "| eval b=len(_raw) | stats count sum(b) AS bytes by index")
        rows = {r["index"]: (int(r["count"]), int(r["bytes"])) for r in res}
        if rows.get("homelab_baseline", (0,))[0] == N:
            break
    (ce, cb), (oe, ob) = rows["homelab_baseline"], rows.get("homelab_auth", (0, 0))
    fails = splunk(f"index=homelab_auth host={RUN} action=failure | stats count")[0]["count"]
    raw_fails = splunk(f"index=homelab_baseline host={RUN} | spath action "
                       "| search action IN (failed, denied) | stats count")[0]["count"]
    assert fails == raw_fails, f"failed logins lost: baseline {raw_fails}, optimized {fails}"
    print(f"""
| Pipeline | Events | Bytes (_raw) | Bytes/Event |
|---|---|---|---|
| unchanged (homelab_baseline) | {ce} | {cb} | {cb / ce:.0f} |
| optimized (homelab_auth) | {oe} | {ob} | {ob / max(oe, 1):.0f} |
| reduction | {(ce - oe) / ce * 100:.1f} % | {(cb - ob) / cb * 100:.1f} % | |

failed logins: baseline {raw_fails}, optimized {fails} (none dropped)""")


if __name__ == "__main__":
    main()
