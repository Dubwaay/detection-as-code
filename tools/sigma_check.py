"""sigma check with the ATT&CK release pinned in tools/attack.py.

pySigma downloads ATT&CK from MITRE's master branch and keeps it in ~/.cache without expiry,
so a local run and a CI run could validate against different releases.
Arguments are passed to sigma check as they are.
"""

import sys
from pathlib import Path

from sigma.cli.check import check
from sigma.data import mitre_attack

from tools import attack

mitre_attack.set_cache_dir(str(Path(__file__).resolve().parent.parent / ".cache" / "pysigma"))
mitre_attack.set_url(str(attack.fetch()))
check.main(args=sys.argv[1:], prog_name="sigma check")
