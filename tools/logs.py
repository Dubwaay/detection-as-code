"""Download test datasets and parse them into events."""

import hashlib
import re
import shutil
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

from tools.cases import Dataset

CACHE = Path(__file__).resolve().parent.parent / ".cache" / "datasets"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, expected: str, path: Path) -> Path:
    """path, downloaded from url unless it is already there with the expected sha256."""
    if path.is_file() and sha256(path) == expected:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=60) as response, partial.open("wb") as f:
        shutil.copyfileobj(response, f)
    actual = sha256(partial)
    if actual != expected:
        partial.unlink()
        raise ValueError(f"{url}: sha256 is {actual}, expected {expected}")
    partial.replace(path)
    return path


def fetch(dataset: Dataset) -> Path:
    """Path to the dataset file, downloaded into the cache on first use."""
    return download(str(dataset.url), dataset.sha256, CACHE / dataset.sha256)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]  # drop the XML namespace


def xml_events(path: Path) -> Iterator[dict[str, str]]:
    """Windows events exported as XML (XmlWinEventLog). A value can span lines."""
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"<Event\b.*?</Event>", text, re.DOTALL):
        event = ET.fromstring(match.group())
        fields = {}
        for part in event:
            if _local(part.tag) == "System":
                for item in part:
                    name = _local(item.tag)
                    if item.text and item.text.strip():
                        fields[name] = item.text
                    for attr, value in item.attrib.items():
                        fields[f"{name}_{attr}"] = value  # e.g. Provider_Name
            elif _local(part.tag) == "EventData":
                for item in part:
                    if "Name" in item.attrib:
                        fields[item.attrib["Name"]] = item.text
        yield fields


READERS = {"XmlWinEventLog": xml_events}


def events(dataset: Dataset) -> Iterator[dict[str, str]]:
    try:
        reader = READERS[dataset.sourcetype]
    except KeyError:
        raise ValueError(f"no reader for sourcetype {dataset.sourcetype}") from None
    return reader(fetch(dataset))
