"""Download test datasets and parse them into events."""

import hashlib
import io
import re
import shutil
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
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


def _keep(partial: Path, path: Path, expected: str, origin: str) -> Path:
    actual = sha256(partial)
    if actual != expected:
        partial.unlink()
        raise ValueError(f"{origin}: sha256 is {actual}, expected {expected}")
    partial.replace(path)
    return path


def download(url: str, expected: str, path: Path) -> Path:
    """path, downloaded from url unless it is already there with the expected sha256."""
    if path.is_file() and sha256(path) == expected:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=60) as response, partial.open("wb") as f:
        shutil.copyfileobj(response, f)
    return _keep(partial, path, expected, url)


class RangeReader(io.RawIOBase):
    """A remote file read with HTTP range requests, so zipfile can seek in it."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.pos = 0
        _, self.size = self._get(0, 0)

    def _get(self, start: int, end: int) -> tuple[bytes, int]:
        request = urllib.request.Request(self.url, headers={"Range": f"bytes={start}-{end}"})
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 206:
                raise ValueError(f"{self.url}: the server ignores range requests")
            total = int(response.headers["Content-Range"].rpartition("/")[2])
            return response.read(), total

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self.pos, io.SEEK_END: self.size}[whence]
        self.pos = base + offset
        return self.pos

    def readinto(self, buffer) -> int:
        if self.pos >= self.size:
            return 0
        data, _ = self._get(self.pos, min(self.pos + len(buffer), self.size) - 1)
        buffer[: len(data)] = data
        self.pos += len(data)
        return len(data)


def download_member(url: str, member: str, expected: str, path: Path) -> Path:
    """path, extracted from the zip at url unless it is already there with the expected sha256.

    Only the archive index and the member are downloaded. Public datasets ship whole hosts in
    archives of hundreds of MB, while a test needs one log file.
    """
    if path.is_file() and sha256(path) == expected:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(".part")
    remote = io.BufferedReader(RangeReader(url), buffer_size=1 << 20)
    with zipfile.ZipFile(remote) as archive, archive.open(member) as src, partial.open("wb") as f:
        shutil.copyfileobj(src, f, 1 << 20)
    return _keep(partial, path, expected, f"{url} {member}")


def fetch(dataset: Dataset) -> Path:
    """Path to the dataset file, downloaded into the cache on first use."""
    path = CACHE / dataset.sha256
    if dataset.member:
        return download_member(str(dataset.url), dataset.member, dataset.sha256, path)
    return download(str(dataset.url), dataset.sha256, path)


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


AUDIT_LINE = re.compile(r"type=(?P<type>\S+) msg=audit\([^)]*\)\s*:\s*(?P<body>.*)")
# A value is quoted or ends at a space, a quote or the 0x1d byte. Python's \s covers 0x1d.
AUDIT_FIELD = re.compile(r"(?<![\w-])([A-Za-z_][\w-]*)=(\"[^\"]*\"|[^\s'\"]*)")


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
        record = {"type": match["type"]}
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
