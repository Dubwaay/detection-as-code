"""Run a Sigma rule over log events in SQLite."""

import re
import sqlite3
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline


def run(rule_path: Path, events: list[dict[str, str]]) -> list[dict[str, str]]:
    """Events the rule matches."""
    rule = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    # pySigma writes the SQL; the Sysmon pipeline turns category process_access into EventID=10.
    (query,) = sqliteBackend(sysmon_pipeline()).convert(rule)

    # Sysmon spells one field two ways (SourceProcessGUID, SourceProcessGuid) and SQLite column
    # names ignore case, so both go into one column.
    columns = {}  # lower-case name -> first spelling seen
    for event in events:
        for name in event:
            columns.setdefault(name.lower(), name)
    rows = []
    for event in events:
        lowered = {name.lower(): value for name, value in event.items()}
        rows.append([lowered.get(key) for key in columns])

    db = sqlite3.connect(":memory:")
    # SQLite has the REGEXP operator but no function behind it. |re in a rule needs one.
    db.create_function(
        "REGEXP",
        2,
        lambda pattern, value: value is not None and re.search(pattern, value) is not None,
    )
    # Sigma matches strings case-insensitively; NOCASE makes "=" do the same.
    spec = ", ".join(f'"{name}" TEXT COLLATE NOCASE' for name in columns.values())
    db.execute(f"CREATE TABLE logs ({spec})")
    db.executemany(f"INSERT INTO logs VALUES ({', '.join('?' * len(columns))})", rows)
    while True:
        try:
            cursor = db.execute(query)
            break
        except sqlite3.OperationalError as error:
            # A field the rule checks can be absent from every event, like a0 of EXECVE in a
            # log of PROCTITLE records. An empty column lets that part of the rule not match.
            missing = re.fullmatch(r"no such column: (\w+)", str(error))
            if not missing:
                raise
            db.execute(f'ALTER TABLE logs ADD COLUMN "{missing[1]}" TEXT COLLATE NOCASE')
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor]
