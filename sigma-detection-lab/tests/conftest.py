import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "scripts")]


@pytest.fixture(scope="session")
def fixtures() -> list[dict]:
    lines = (ROOT / "tests" / "fixtures" / "auth-events.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.fixture(scope="session")
def rules() -> dict:
    from sigma_eval import load_rules
    return load_rules(ROOT / "rules")
