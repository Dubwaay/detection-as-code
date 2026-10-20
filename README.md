# detection-as-code

Detections written as Sigma (and Splunk SPL where Sigma cannot express the logic), each tested
against public attack datasets.

Work in progress.

## Layout

One folder per detection, grouped by platform:

| Path | What |
|---|---|
| `detections/<platform>/<name>/sigma.yml` | Sigma rule (plain Sigma) |
| `detections/<platform>/<name>/splunk.spl` | hand-written SPL counterpart (optional) |
| `detections/<platform>/<name>/tests.yml` | test cases: attack logs the rule must fire on, normal logs it must stay silent on |
| `detections/<platform>/<name>/README.md` | detection card: hypothesis, logic, noise measured in Splunk, triage, limitations |
