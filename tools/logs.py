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


AUDIT_LINE = re.compile(r"type=(?P<type>\S+) msg=audit\((?P<stamp>[^)]*)\)\s*:\s*(?P<body>.*)")
AUDIT_FIELD = re.compile(r'(\w+)=("[^"]*"|\S*)')
HEX = re.compile(r"(?:[0-9A-F]{2})+")


def auditd_records(path: Path) -> Iterator[dict[str, str]]:
    """auditd records, one per line, from audit.log or from ausearch -i.

    In audit.log a proctitle or an EXECVE argument with a space or a NUL is written as hex.
    Those values are decoded with NUL turned into a space, as ausearch -i shows them.
    """
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = AUDIT_LINE.match(line)
        if not match:
            continue
        kind = match["type"]
        # audit.log stamps with epoch seconds, ausearch -i with a date
        raw = re.fullmatch(r"\d+\.\d+:\d+", match["stamp"])
        # audit.log adds the same fields in readable form after \x1d (ARCH=, SYSCALL=, AUID=).
        # SQLite column names ignore case, so SYSCALL would overwrite syscall.
        body = match["body"].partition("\x1d")[0].rstrip()
        # ausearch -i prints proctitle decoded, spaces included, as the only field
        if kind == "PROCTITLE" and body.startswith("proctitle=") and " " in body:
            fields = [("proctitle", body.removeprefix("proctitle="))]
        else:
            fields = AUDIT_FIELD.findall(body)
        record = {"type": kind}
        for name, value in fields:
            if value.startswith('"'):
                value = value.strip('"')
            elif (
                raw
                and (name == "proctitle" or (kind == "EXECVE" and re.fullmatch(r"a\d+", name)))
                and HEX.fullmatch(value)
            ):
                value = bytes.fromhex(value).replace(b"\0", b" ").decode(errors="replace").strip()
            record[name] = value
        yield record


READERS = {"XmlWinEventLog": xml_events, "auditd": auditd_records}


def events(dataset: Dataset) -> Iterator[dict[str, str]]:
    try:
        reader = READERS[dataset.sourcetype]
    except KeyError:
        raise ValueError(f"no reader for sourcetype {dataset.sourcetype}") from None
    return reader(fetch(dataset))
