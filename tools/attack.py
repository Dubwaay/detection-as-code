"""MITRE ATT&CK release that sigma check validates the rule tags against.

Run as a script to compare the pinned release with the latest one from MITRE.
"""

import json
import sys
import urllib.request
from pathlib import Path

from tools.logs import download

VERSION = "20.0"
SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"v{VERSION}/enterprise-attack/enterprise-attack-{VERSION}.json"
)
INDEX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
CACHE = Path(__file__).resolve().parent.parent / ".cache" / "attack"


def fetch() -> Path:
    """Path to the pinned STIX bundle, downloaded into the cache on first use."""
    return download(URL, SHA256, CACHE / f"enterprise-attack-{VERSION}.json")


def latest() -> str:
    """Newest Enterprise ATT&CK version listed in MITRE's index.json."""
    with urllib.request.urlopen(INDEX, timeout=60) as response:
        index = json.load(response)
    (enterprise,) = (c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
    versions = [v["version"] for v in enterprise["versions"]]
    return max(versions, key=lambda v: tuple(int(part) for part in v.split(".")))


if __name__ == "__main__":
    newest = latest()
    print(f"pinned ATT&CK {VERSION}, latest {newest}")
    if newest != VERSION:
        print("update VERSION and SHA256 in tools/attack.py")
        sys.exit(1)
