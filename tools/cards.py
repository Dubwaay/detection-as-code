"""ADS cards: the README.md next to each rule, read into sections."""

import re
from dataclasses import dataclass
from pathlib import Path

# Palantir ADS order, except that Validation comes before Priority
SECTIONS = [
    "Goal",
    "Categorization",
    "Strategy Abstract",
    "Technical Context",
    "Blind Spots and Assumptions",
    "False Positives",
    "Validation",
    "Priority",
    "Response",
    "Additional Resources",
]

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
CODE = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
FIELD = re.compile(r"^(\w+):\s+(.*)$")


@dataclass
class Card:
    text: str
    title: str
    order: list[str]
    sections: dict[str, str]


def read(path: Path) -> Card:
    text = path.read_text(encoding="utf-8")
    head, *rest = re.split(r"^## (.+)\n", text, flags=re.MULTILINE)
    first = head.splitlines()[0] if head else ""
    title = first.removeprefix("# ") if first.startswith("# ") else ""
    order = rest[0::2]
    return Card(text, title, order, dict(zip(order, rest[1::2], strict=True)))


def links(text: str) -> list[str]:
    return LINK.findall(text)


def example_events(text: str) -> list[dict[str, str]]:
    """Field: value pairs of each code block. An indented line continues the previous value."""
    events = []
    for block in CODE.findall(text):
        fields: dict[str, str] = {}
        last = None
        for line in block.splitlines():
            if line[:1].isspace() and last:
                fields[last] += line.strip()
            elif match := FIELD.match(line):
                last = match.group(1)
                fields[last] = match.group(2).rstrip()
        if fields:
            events.append(fields)
    return events
