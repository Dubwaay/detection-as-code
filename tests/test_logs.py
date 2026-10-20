"""Each rule against the logs in its tests.yml, run in SQLite."""

import re
from pathlib import Path

import pytest
import yaml

from tools import logs, replay
from tools.cases import Case, CaseFile

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = sorted(p for p in (ROOT / "detections").glob("*/*") if p.is_dir())


def cases() -> list:
    params = []
    for folder in FOLDERS:
        path = folder / "tests.yml"
        tests = CaseFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        for case in tests.cases:
            name = f"{folder.parent.name}/{folder.name}/{case.name}"
            params.append(pytest.param(folder, case, id=name))
    return params


def matches(value: str | None, pattern: str) -> bool:
    """Splunk-style wildcard match: * is any text, case does not matter."""
    regex = ".*".join(re.escape(part) for part in pattern.split("*"))
    return value is not None and re.fullmatch(regex, value, re.IGNORECASE) is not None


@pytest.mark.parametrize(("folder", "case"), cases())
def test_rule_on_logs(folder: Path, case: Case) -> None:
    (rule_path,) = (p for p in folder.glob("*.yml") if p.name != "tests.yml")
    events = [event for dataset in case.datasets for event in logs.events(dataset)]
    results = replay.run(rule_path, events)

    expect = case.expect
    if expect.min_results is not None:
        assert len(results) >= expect.min_results, f"{len(results)} results"
    if expect.max_results is not None:
        assert len(results) <= expect.max_results, f"{len(results)} results"
    for field in expect.fields_present:
        assert all(row.get(field) for row in results), f"{field} is empty in some results"
    if expect.match:
        assert any(
            all(matches(row.get(f), p) for f, p in expect.match.items()) for row in results
        ), f"no result matches {expect.match}"
