#!/usr/bin/env bash
# Open an issue when MITRE has an ATT&CK release newer than the one pinned in tools/attack.py.
# The job always ends green: a failed scheduled run would mark the last commit on main as failed.
# Needs gh with GH_TOKEN allowed to write issues. RUN_URL links the issue to the workflow run.
set -euo pipefail

# open an issue unless one with the same title is already open
issue() {
  local title=$1 body=$2
  if gh issue list --state open --search "\"$title\" in:title" --json title --jq '.[].title' |
    grep -qxF "$title"; then
    echo "issue already open: $title"
  else
    gh issue create --title "$title" --body "$body"
  fi
}

if ! versions=$(uv run --locked python -c 'from tools import attack; print(attack.VERSION, attack.latest())'); then
  issue "ATT&CK release check fails" "Reading MITRE's index.json failed: ${RUN_URL:-see the attack-update workflow}"
  exit 0
fi
read -r pinned latest <<< "$versions"
echo "pinned ATT&CK $pinned, latest $latest"

if [[ ! $latest =~ ^[0-9]+\.[0-9]+$ ]]; then
  issue "ATT&CK release check fails" "MITRE's index.json lists an unexpected version: ${RUN_URL:-see the attack-update workflow}"
elif [[ $latest != "$pinned" ]]; then
  issue "Update ATT&CK to $latest" \
    "MITRE released ATT&CK $latest. Set VERSION and SHA256 in tools/attack.py to it and run the checks."
fi
