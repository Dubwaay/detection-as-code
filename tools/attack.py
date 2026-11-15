"""MITRE ATT&CK release that sigma check validates the rule tags against.

Run as a script to compare the pinned release with the latest one from MITRE.
"""

import json
import sys
import urllib.request
from pathlib import Path

from tools.datasets import download

VERSION = "20.1"
# Pinned by commit: MITRE moved the v20.0 tag after that release.
COMMIT = "f59b03ecf828579d5f9e93683ce25b7e2e5fd9d7"
SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"{COMMIT}/enterprise-attack/enterprise-attack-{VERSION}.json"
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
        print("update VERSION, COMMIT and SHA256 in tools/attack.py")
        sys.exit(1)
