"""Checks that sigma check cannot do: folder layout and test cases."""

from pathlib import Path

import pytest
import yaml

from tools.cases import CaseFile

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = sorted(p for p in (ROOT / "detections").glob("*/*") if p.is_dir())


@pytest.mark.parametrize("folder", FOLDERS, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_detection_folder(folder: Path) -> None:
    rules = [p for p in folder.glob("*.yml") if p.name != "tests.yml"]
    assert len(rules) == 1, "a detection folder holds exactly one Sigma rule"
    assert (folder / "tests.yml").is_file(), "tests.yml is missing"

    rule = yaml.safe_load(rules[0].read_text(encoding="utf-8"))
    tests = CaseFile.model_validate(
        yaml.safe_load((folder / "tests.yml").read_text(encoding="utf-8"))
    )

    assert str(tests.rule_id) == rule["id"], "tests.yml points to another rule"
    assert any(c.expect.min_results for c in tests.cases), "no case the rule must fire on"
    assert any(c.expect.max_results == 0 for c in tests.cases), "no case it must stay silent on"
