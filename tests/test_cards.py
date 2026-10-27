"""ADS cards: layout, agreement with the rule, and the example event, if any, in the test logs."""

import re
from pathlib import Path

import pytest
import yaml

from tools import cards, logs
from tools.cases import CaseFile

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = sorted(p for p in (ROOT / "detections").glob("*/*") if p.is_dir())


def folder_id(folder: Path) -> str:
    return f"{folder.parent.name}/{folder.name}"


def load(folder: Path) -> tuple[dict, cards.Card]:
    (rule_path,) = (p for p in folder.glob("*.yml") if p.name != "tests.yml")
    rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    card_path = folder / "README.md"
    assert card_path.is_file(), "README.md is missing"
    return rule, cards.read(card_path)


def same(value: str | None, shown: str) -> bool:
    """The card shows values with whitespace collapsed, and a trailing ... cuts a long value."""
    if value is None:
        return False
    value = " ".join(value.split())
    if shown.endswith("..."):
        return value.startswith(" ".join(shown.removesuffix("...").split()))
    return value == " ".join(shown.split())


@pytest.mark.parametrize("folder", FOLDERS, ids=folder_id)
def test_card_layout(folder: Path) -> None:
    rule, card = load(folder)
    assert card.order == cards.SECTIONS, f"sections differ from the ADS order: {card.order}"
    assert card.title == rule["title"], "the card title differs from the rule title"

    blind = card.sections["Blind Spots and Assumptions"]
    assert re.search(r"^Blind spots\n\n- .*^Assumptions\n\n- ", blind, re.MULTILINE | re.DOTALL), (
        "Blind spots and Assumptions lists are missing"
    )
    assert "| Source | How to recognise it | Handling |" in card.sections["False Positives"], (
        "the false positives table has another header"
    )
    steps = re.findall(r"^(\d+)\. (.*)$", card.sections["Response"], re.MULTILINE)
    assert steps, "Response has no numbered steps"
    assert [int(n) for n, _ in steps] == list(range(1, len(steps) + 1)), "Response steps skip"
    assert "escalate" in steps[-1][1], "the last Response step is not the escalation"


@pytest.mark.parametrize("folder", FOLDERS, ids=folder_id)
def test_card_matches_rule(folder: Path) -> None:
    rule, card = load(folder)
    tags = [t.removeprefix("attack.") for t in rule.get("tags", []) if t.startswith("attack.")]
    techniques = {t.upper() for t in tags if re.fullmatch(r"t\d{4}(\.\d{3})?", t)}
    tactics = {t for t in tags if not re.fullmatch(r"[tgs]\d{4}(\.\d{3})?", t)}

    category = card.sections["Categorization"]
    linked = re.findall(
        r"\]\(https://attack\.mitre\.org/techniques/(T\d{4})/(?:(\d{3})/)?\)", category
    )
    assert {f"{t}.{sub}" if sub else t for t, sub in linked} == techniques, (
        "Categorization techniques differ from the rule tags"
    )
    names = re.findall(r"\[([^\]]+)\]\(https://attack\.mitre\.org/tactics/TA\d{4}/\)", category)
    assert {n.lower().replace(" ", "-") for n in names} == tactics, (
        "Categorization tactics differ from the rule tags"
    )

    assert card.sections["Priority"].strip().startswith(rule["level"].capitalize()), (
        f"Priority does not start with the rule level {rule['level']}"
    )
    validation = card.sections["Validation"]
    assert "[tests.yml](tests.yml)" in validation, "Validation does not link tests.yml"
    assert "tools/goodlog.sh" in validation, "Validation does not link tools/goodlog.sh"

    for target in cards.links(card.text):
        if re.match(r"[a-z]+:", target) or target.startswith("#"):
            continue
        assert (folder / target.split("#")[0]).exists(), f"broken link: {target}"


@pytest.mark.parametrize("folder", FOLDERS, ids=folder_id)
def test_card_example_event(folder: Path) -> None:
    _, card = load(folder)
    examples = cards.example_events(card.sections["Technical Context"])
    if not examples:
        pytest.skip("Technical Context has no example event")

    tests = CaseFile.model_validate(
        yaml.safe_load((folder / "tests.yml").read_text(encoding="utf-8"))
    )
    datasets = {d.sha256: d for case in tests.cases for d in case.datasets}.values()
    events = [event for dataset in datasets for event in logs.events(dataset)]
    for shown in examples:
        assert any(all(same(event.get(f), v) for f, v in shown.items()) for event in events), (
            f"no event in the test logs matches the example {shown}"
        )
