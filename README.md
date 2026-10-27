# detection-as-code

[![CI](https://github.com/Dubwaay/detection-as-code/actions/workflows/ci.yml/badge.svg)](https://github.com/Dubwaay/detection-as-code/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Rules: Sigma](https://img.shields.io/badge/rules-Sigma-orange.svg)](https://sigmahq.io/)

Sigma detection rules that are checked on public logs before they are merged. A rule must fire
on the attack logs listed in its test cases and stay silent on normal activity. Each rule comes
with a detection card that covers its blind spots, false positives and triage steps.

- [Repository layout](#repository-layout)
- [How a rule is checked](#how-a-rule-is-checked)
- [Detection cards](#detection-cards)
- [Quick start](#quick-start)
- [Converting rules for a SIEM](#converting-rules-for-a-siem)
- [Adding a rule](#adding-a-rule)
- [Sources](#sources)
- [License](#license)

## Repository layout

| Path | Contents |
|---|---|
| [`detections/`](detections) | Rules grouped by platform, one folder per rule |
| [`tests/`](tests) | pytest checks for rules, test cases and cards |
| [`tools/`](tools) | Log readers, SQLite replay, card parser, goodlog script, pinned ATT&CK release |
| [`.github/workflows/`](.github/workflows) | CI and the weekly ATT&CK release check |

Every rule folder has the same three files:

```
detections/<platform>/<name>/
├── <rule>.yml    Sigma rule, file named as in SigmaHQ
├── tests.yml     test cases: log URL, sha256, what the rule must find
└── README.md     detection card
```

## How a rule is checked

| Check | What it does | Runs in |
|---|---|---|
| [`tools/sigma_check.py`](tools/sigma_check.py) | Runs `sigma check`: syntax, rule IDs and ATT&CK tags against the release pinned in [`tools/attack.py`](tools/attack.py) | pre-commit, CI |
| [`tests/test_detections.py`](tests/test_detections.py) | One rule and one `tests.yml` per folder, at least one case the rule must fire on and one it must stay silent on | pre-commit, CI |
| [`tests/test_logs.py`](tests/test_logs.py) | Runs the rule over the logs from `tests.yml`. pySigma converts the rule to SQL and SQLite runs it over the parsed events | pre-commit, CI |
| [`tests/test_cards.py`](tests/test_cards.py) | The card follows the ADS section order, its title, ATT&CK tags, level and links match the rule, its example event exists in the test logs | pre-commit, CI |
| [`tools/goodlog.sh`](tools/goodlog.sh) | Runs all rules over clean Windows logs from [evtx-baseline](https://github.com/NextronSystems/evtx-baseline) with evtx-sigma-checker. A hit fails the run unless it is listed in [`tools/goodlog-known-fps.csv`](tools/goodlog-known-fps.csv) | CI, five baselines |
| [`tools/attack_update.sh`](tools/attack_update.sh) | Opens an issue when MITRE has an ATT&CK release newer than the one pinned in `tools/attack.py` | CI, weekly |

Test logs and the ATT&CK release are downloaded into `.cache/` and checked against their
sha256. They are not stored in the repo.

When MITRE publishes a new ATT&CK release, the weekly check opens an issue. Set `VERSION` and
`SHA256` in `tools/attack.py` to the new release and run the checks.

## Detection cards

The `README.md` next to each rule follows the
[Palantir Alerting and Detection Strategy framework](https://github.com/palantir/alerting-detection-strategy-framework):
Goal, Categorization, Strategy Abstract, Technical Context, Blind Spots and Assumptions,
False Positives, Validation, Priority, Response, Additional Resources.
Validation names an Atomic Red Team test that makes the rule fire and lists the results on the
test logs. Example: [LSASS memory access](detections/windows/lsass_memory_access/README.md).

## Quick start

You need Python 3.12 and [uv](https://docs.astral.sh/uv/getting-started/installation/).
goodlog also needs bash, curl, tar and Linux on x86-64, since it runs a Linux binary.
On Windows use WSL.

```bash
git clone https://github.com/Dubwaay/detection-as-code.git
cd detection-as-code
uv sync --locked
uv run pytest
uv run python -m tools.sigma_check -i $(find detections -name '*.yml' ! -name tests.yml)
```

Run the rules over a clean baseline. The baseline and the checker are downloaded once into
`.cache/goodlog/`:

```bash
tools/goodlog.sh win10-client
```

Baselines: `win10-client`, `win2022-ad`, `win11-client`, `win2022-0-20348-azure`, `win2022-evtx`.

Run the same checks on every commit:

```bash
uv tool install pre-commit
pre-commit install
```

## Converting rules for a SIEM

Use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) with the backend for your SIEM.
For Splunk:

```bash
uvx --from sigma-cli==3.1.0 --with pysigma-backend-splunk==2.1.0 --with pysigma-pipeline-sysmon==2.0.0 \
  sigma convert -t splunk -p sysmon detections/windows/lsass_memory_access/proc_access_win_lsass_memory_access.yml
```

The `sysmon` pipeline turns the Sigma log source into Sysmon event IDs. Add the index or
source of your Sysmon data to the search. Backends for other SIEMs are listed in the
[pySigma docs](https://sigmahq.io/docs/digging-deeper/backends.html).

## Adding a rule

1. Create `detections/<platform>/<name>/` and put the Sigma rule there. Name the file as
   SigmaHQ does, for example `proc_creation_win_<name>.yml`.
2. Add `tests.yml` with at least one log the rule must fire on (`min_results`) and one it must
   stay silent on (`max_results: 0`). The format is defined in [`tools/cases.py`](tools/cases.py).
   Logs are read by `sourcetype`. [`tools/logs.py`](tools/logs.py) has readers for
   `XmlWinEventLog`, the Windows event logs in splunk/attack_data, and `auditd`, Linux audit
   records from audit.log or `ausearch -i`.
3. Add `README.md` with the detection card. An existing card shows the expected sections.
4. Run `uv run pytest`, and `tools/goodlog.sh` for Windows rules.
5. Open a pull request. CI runs the same checks.

## Sources

- [Sigma specification](https://github.com/SigmaHQ/sigma-specification),
  [pySigma](https://github.com/SigmaHQ/pySigma) and
  [sigma-cli](https://github.com/SigmaHQ/sigma-cli).
- [splunk/attack_data](https://github.com/splunk/attack_data) (Apache-2.0): attack logs for
  the test cases.
- [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) (Apache-2.0):
  clean Windows logs and evtx-sigma-checker for goodlog.
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma): `tests/thor.yml`, the mapping of Sigma log
  sources to Windows channels used by goodlog.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MIT): tests named in the
  cards to make a rule fire.
- Splunk [BOTS v1](https://github.com/splunk/botsv1), [v2](https://github.com/splunk/botsv2)
  and [v3](https://github.com/splunk/botsv3) (CC0): extra checks in Splunk, results are in
  the cards.
- [Palantir ADS framework](https://github.com/palantir/alerting-detection-strategy-framework)
  (MIT): the card format.
- [MITRE ATT&CK](https://attack.mitre.org/), STIX data from
  [attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

## License

MIT, see [LICENSE](LICENSE). Downloaded data keeps the license of its source.
