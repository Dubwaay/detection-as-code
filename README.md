# detection-as-code

Sigma rules, each tested against public attack logs: the rule has to fire
on the attack and stay quiet on normal activity. Work in progress.

## Layout

```
detections/<platform>/<name>/
  <rule>.yml   Sigma rule, file named as in SigmaHQ
  tests.yml    test cases: log URL, sha256, what the rule should find
```

## Checks

On every commit (pre-commit):

- `sigma check`: rule syntax, ATT&CK tags, duplicate ids
- `pytest`: folder layout and tests.yml format, then every rule is run
  against the logs from its tests.yml (pySigma converts it to SQL, SQLite runs it)

Logs are not stored in the repo. They are downloaded by URL and checked
against the sha256 from tests.yml.

## Running locally

```
uv sync
uv run pytest
```

To run the same checks on every commit:

```
uv tool install pre-commit
pre-commit install
```
