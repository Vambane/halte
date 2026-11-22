"""Guard a timetable refresh: compare a new snapshot with the committed one.

The MyCiTi downloads page is flaky (it has listed 40 routes instead of 47),
so a scrape on a bad day can quietly lose routes. This refuses a snapshot in
which any network lost more than MAX_LOSS of its routes or departures.

Usage:
    python tools/check_snapshot.py OLD_SNAPSHOT_DIR NEW_SNAPSHOT_DIR

Exit status 0 when the new snapshot is safe to propose, 1 otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

import duckdb

MAX_LOSS = 0.10  # refuse if a network lost more than 10%


def counts(snapshot: Path) -> dict[tuple[str, str], int]:
    """(operator, 'routes'|'departures') -> count for one snapshot directory."""
    con = duckdb.connect()
    out: dict[tuple[str, str], int] = {}
    for table, what in (("routes", "COUNT(DISTINCT route_id)"), ("departures", "COUNT(*)")):
        path = str(snapshot / f"{table}.parquet")
        rows = con.execute(
            f"SELECT operator, {what} FROM read_parquet(?) GROUP BY operator", [path]
        ).fetchall()
        for operator, n in rows:
            out[(operator, table)] = n
    return out


def problems(old: dict[tuple[str, str], int], new: dict[tuple[str, str], int]) -> list[str]:
    """Human-readable reasons to refuse the new snapshot (empty list = fine)."""
    found = []
    for key, before in sorted(old.items()):
        after = new.get(key, 0)
        if before and after < before * (1 - MAX_LOSS):
            operator, table = key
            found.append(f"{operator} {table}: {before} -> {after}")
    return found


def main(argv: list[str]) -> int:
    """Print a comparison table and return the exit status."""
    if len(argv) != 3:
        print(__doc__)
        return 2
    old, new = counts(Path(argv[1])), counts(Path(argv[2]))
    for key in sorted(set(old) | set(new)):
        print(f"{key[0]:10} {key[1]:11} {old.get(key, 0):>8} -> {new.get(key, 0):>8}")
    bad = problems(old, new)
    for line in bad:
        print(f"REFUSED: lost more than {MAX_LOSS:.0%}: {line}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
