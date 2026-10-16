#!/usr/bin/env bash
# Sends a fresh login burst (timestamps = now) to the Cribl HTTP source.
# Usage: ./scripts/send-events.sh [failures=3] [cribl_url]
#   3 failures -> alert must fire, 2 failures -> alert must stay quiet
set -euo pipefail
n=${1:-3}
url=${2:-http://localhost:10080/cribl/_bulk}

ev() {
  printf '{"event_time":"%s","host":"lab-linux-01","user":"%s","src":"%s","dest":"lab-linux-01","action":"%s","service":"ssh","environment":"homelab"}\n' \
    "$(date -u +%FT%TZ)" "$1" "$2" "$3"
}

{
  ev alice 192.0.2.10 success
  for _ in $(seq "$n"); do ev bob 192.0.2.20 failure; done
  ev bob 192.0.2.20 success
} | curl -fsS --data-binary @- "$url"
echo "sent $n failures to $url"
