#!/usr/bin/env bash
# Run the rules over clean Windows event logs from NextronSystems/evtx-baseline.
# A rule that fires there is a false positive candidate, so the script fails.
# Usage: tools/goodlog.sh win10-client
set -euo pipefail

baseline=${1:?usage: tools/goodlog.sh <baseline, e.g. win10-client>}
release=https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.5
cache=.cache/goodlog
mkdir -p "$cache"

# download once, check the sha256 on every run
get() {
  local url=$1 sha=$2 file=$cache/$3
  if [[ ! -f $file ]]; then
    curl -fsSL -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  echo "$sha  $file" | sha256sum --check --quiet
}

case $baseline in
  win10-client) sha=d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e ;;
  win2022-ad) sha=dde89557c8dd19756d1fb4797f566aaa94509847c2740968bf04b5bea0b34ec1 ;;
  *) echo "unknown baseline: $baseline" >&2; exit 2 ;;
esac
get "$release/$baseline.tgz" "$sha" "$baseline.tgz"
get "$release/evtx-sigma-checker" \
  d672e07a516f3f72eaae8244f99fa2c5b133885a4401eb05a272903857d767e2 evtx-sigma-checker
# SigmaHQ's mapping of Sigma log sources to Windows channels and event IDs
get https://raw.githubusercontent.com/SigmaHQ/sigma/a4ddc7a4140c7e0e9a1d92481a1ff91d9237e774/tests/thor.yml \
  8e72d9223e2c3c1d2d647b08e10118a3a067975ce7eba37dc1623f9d79604120 thor.yml
chmod +x "$cache/evtx-sigma-checker"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$cache/$baseline.tgz" -C "$work"
# copy only the rules: the checker tries to load every .yml as a rule
mkdir "$work/rules"
find detections -name '*.yml' ! -name tests.yml -exec cp {} "$work/rules/" \;

"$cache/evtx-sigma-checker" --log-source "$cache/thor.yml" --evtx-path "$work" \
  --rule-path "$work/rules" --rule-level informational > "$work/findings.json"

if [[ -s $work/findings.json ]]; then
  echo "rules fired on clean $baseline logs:"
  python3 -c '
import json, sys
for line in sys.stdin:
    hit = json.loads(line)
    print(hit["RuleTitle"] + ": " + hit["Event"][:300])
' < "$work/findings.json"
  exit 1
fi
echo "no rule fired on $baseline"
