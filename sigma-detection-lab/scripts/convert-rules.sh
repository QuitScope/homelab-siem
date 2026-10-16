#!/usr/bin/env bash
# Regenerates generated/ from rules/ (official pySigma Splunk backend + pipelines/splunk/homelab.yml).
# Never edit generated/ by hand: the test suite and CI fail if the committed files are out of date.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run python scripts/convert_rules.py
