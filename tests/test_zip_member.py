"""Downloading one log file from a zip archive with HTTP range requests."""

import hashlib
import io
import os
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools.logs import download_member

LOG = b"type=PROCTITLE msg=audit(1758539807.929:13085): proctitle=636174\n" * 100
LOG_SHA256 = hashlib.sha256(LOG).hexdigest()


def archive() -> bytes:
    """A zip with the log and 4 MB of other data that the download must skip."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("host/traffic.pcap", os.urandom(4 << 20), zipfile.ZIP_STORED)
        z.writestr("host/audit.log", LOG, zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


@pytest.fixture
def serve():
    """Start a local server for a body. Returns its URL and the byte counts it sent."""
    servers = []

    def start(body: bytes, ranges: bool = True) -> tuple[str, list[int]]:
        sent = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                start, end, status = 0, len(body) - 1, 200
                if ranges and "Range" in self.headers:
                    first, last = self.headers["Range"].removeprefix("bytes=").split("-")
                    start, end, status = int(first), int(last), 206
                chunk = body[start : end + 1]
                self.send_response(status)
                if status == 206:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{len(body)}")
                self.send_header("Content-Length", str(len(chunk)))
                self.end_headers()
                try:
                    self.wfile.write(chunk)
                except ConnectionError:  # the client stops reading a 200 response
                    return
                sent.append(len(chunk))

            def log_message(self, *args) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}/logs.zip", sent

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_only_the_member_is_downloaded(serve, tmp_path: Path) -> None:
    body = archive()
    url, sent = serve(body)
    path = download_member(url, "host/audit.log", LOG_SHA256, tmp_path / "log")
    assert path.read_bytes() == LOG
    assert sum(sent) < len(body) // 2


def test_cached_file_is_not_downloaded_again(serve, tmp_path: Path) -> None:
    url, sent = serve(archive())
    path = tmp_path / "log"
    path.write_bytes(LOG)
    assert download_member(url, "host/audit.log", LOG_SHA256, path) == path
    assert sent == []


def test_wrong_sha256_keeps_nothing(serve, tmp_path: Path) -> None:
    url, _ = serve(archive())
    with pytest.raises(ValueError, match="sha256"):
        download_member(url, "host/audit.log", "0" * 64, tmp_path / "log")
    assert list(tmp_path.iterdir()) == []


def test_server_without_ranges_is_an_error(serve, tmp_path: Path) -> None:
    url, _ = serve(archive(), ranges=False)
    with pytest.raises(ValueError, match="range"):
        download_member(url, "host/audit.log", LOG_SHA256, tmp_path / "log")
