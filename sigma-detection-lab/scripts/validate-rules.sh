#!/usr/bin/env bash
# Sigma syntax + metadata validation (pySigma validators, incl. ATT&CK tag check). Any issue fails.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run sigma check --fail-on-issues rules/
