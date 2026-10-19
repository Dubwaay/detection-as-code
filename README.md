# sigma-detections

Sigma detection rules, each tested against public attack datasets.

Work in progress.

## Layout

| Path | What |
|---|---|
| `rules/<product>/<category>/` | Sigma rules |
| `tests/cases/<rule id>.yml` | test cases: attack logs the rule must fire on, normal logs it must stay silent on |
