"""Parse dataset files into events, one dict of field names and values per event.

The reader is picked by the sourcetype of the dataset. Each reader sets `_time`, the time of
the event in ISO 8601 UTC, as Splunk does. Correlation rules count events in windows of it.
"""

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from tools.cases import Dataset
from tools.datasets import fetch


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
        if "TimeCreated_SystemTime" in fields:
            fields["_time"] = fields["TimeCreated_SystemTime"]
        yield fields


AUDIT_LINE = re.compile(r"type=(?P<type>\S+) msg=audit\((?P<stamp>[^)]*)\)\s*:\s*(?P<body>.*)")
# A value is quoted or ends at a space, a quote or the 0x1d byte. Python's \s covers 0x1d.
AUDIT_FIELD = re.compile(r"(?<![\w-])([A-Za-z_][\w-]*)=(\"[^\"]*\"|[^\s'\"]*)")


def _audit_time(stamp: str) -> str:
    """Time of msg=audit(1758539807.929:13085) or msg=audit(11/24/2025 14:24:20.595:327520).

    The second form is printed by `ausearch -i` in local time without a zone. It is read as UTC.
    """
    when = stamp.rpartition(":")[0]
    if "/" in when:
        moment = datetime.strptime(when, "%m/%d/%Y %H:%M:%S.%f").replace(tzinfo=UTC)
    else:
        moment = datetime.fromtimestamp(float(when), UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def linux_audit_records(path: Path) -> Iterator[dict[str, str]]:
    """Records of a raw audit.log, one per line, with field names as in the log.

    Values stay as written: a proctitle or an EXECVE argument with a space is hex. auditd 3
    appends names of numeric values after a 0x1d byte (syscall=59 ... SYSCALL=execve). Those
    are fields of their own. User-space records wrap their fields in msg='...'.
    """
    # str.splitlines() would also split at 0x1d
    for line in path.read_text(encoding="utf-8", errors="replace").split("\n"):
        match = AUDIT_LINE.match(line)
        if not match:
            continue
        record = {"type": match["type"], "_time": _audit_time(match["stamp"])}
        for name, value in AUDIT_FIELD.findall(match["body"]):
            if name != "msg":
                record[name] = value.strip('"')
        yield record


READERS = {"XmlWinEventLog": xml_events, "linux_audit": linux_audit_records}


def events(dataset: Dataset) -> Iterator[dict[str, str]]:
    try:
        reader = READERS[dataset.sourcetype]
    except KeyError:
        raise ValueError(f"no reader for sourcetype {dataset.sourcetype}") from None
    return reader(fetch(dataset))
