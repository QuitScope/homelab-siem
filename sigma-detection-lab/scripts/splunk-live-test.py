#!/usr/bin/env python3
"""LIVE test (needs the HomeLab stack, NOT run in CI): runs the generated SPL in a real Splunk.

Sends the fixtures (except "live": false) through the Cribl HTTP source -> pipeline -> Splunk, tagged with a
unique host, then executes every generated/spl/*.spl query restricted to that host and compares the hits with
the fixture expectations. Stdlib only; run on the Docker VM from the repo checkout:

  set -a; . /opt/homelab-siem/.env; set +a; python3 sigma-detection-lab/scripts/splunk-live-test.py
"""
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRIBL = "http://localhost:10080/cribl/_bulk"
RUN = "sigma-live-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def splunk(search):
    q = urllib.parse.urlencode({"search": "search " + search, "output_mode": "json", "earliest_time": "0"})
    out = subprocess.run(["docker", "exec", "homelab-siem-splunk-1", "sh", "-c",
                          'curl -sk -u "admin:$SPLUNK_PASSWORD" https://localhost:8089/services/search/jobs/export'
                          ' -d "$0"', q], capture_output=True, text=True, check=True).stdout
    return [json.loads(line)["result"] for line in out.splitlines() if '"result"' in line]


def main():
    fixtures = [json.loads(l) for l in (ROOT / "tests/fixtures/auth-events.jsonl").read_text().splitlines() if l]
    live = [f for f in fixtures if f.get("live", True)]
    body = "".join(json.dumps({**f["event"], "host": RUN}) + "\n" for f in live).encode()
    urllib.request.urlopen(urllib.request.Request(CRIBL, data=body, method="POST")).read()
    print(f"sent {len(live)} fixture events as host={RUN}")
    for _ in range(30):
        time.sleep(5)
        if int(splunk(f"index=homelab_auth host={RUN} | stats count")[0]["count"]) >= len(live):
            break
    else:
        sys.exit("events did not arrive in Splunk")

    by_time = {f["event"]["event_time"]: f for f in live}
    expected_corr = json.loads((ROOT / "tests/fixtures/expected-correlations.json").read_text())
    failed = False
    for spl_file in sorted((ROOT / "generated/spl").glob("*.spl")):
        name, spl = spl_file.stem, spl_file.read_text().strip()
        scoped = f"host={RUN} {spl}"
        if name in expected_corr:
            spec = expected_corr[name]
            got = {tuple(r[f] for f in spec["group_by"]) for r in splunk(scoped)}
            want = {tuple(g) for g in spec["groups"]}
        else:
            got = {by_time[r["event_time"]]["id"] for r in splunk(scoped + " | table event_time")}
            want = {f["id"] for f in live if name in f["expect"]}
        ok = got == want
        failed |= not ok
        print(f"{'PASS' if ok else 'FAIL'} {name}: splunk={sorted(got)} expected={sorted(want)}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
