"""Count Halte page views from the app's ``usage`` log lines.

    python tools/usage_report.py render-logs.txt
    pbpaste | python tools/usage_report.py

Reads any text containing lines like
``2026-11-23 08:15:02,123 - halte.usage - INFO - usage event=journey_search
operator=both day=weekday source=reddit`` (as written by
fastapi_app/services/usage.py; copy them from Render's Logs tab) and prints
views per day, per kind of page, and per source.
"""
from __future__ import annotations

import fileinput
import re
import sys
from collections import Counter

LINE = re.compile(r"(?P<day>\d{4}-\d{2}-\d{2})?.*?\busage (?P<fields>event=\S+(?: \w+=\S+)*)")


def parse(lines) -> list[tuple[str, dict[str, str]]]:
    """(day or '?', fields) for every usage line."""
    rows = []
    for text in lines:
        match = LINE.search(text)
        if match:
            fields = dict(part.split("=", 1) for part in match.group("fields").split())
            rows.append((match.group("day") or "?", fields))
    return rows


def report(rows: list[tuple[str, dict[str, str]]]) -> str:
    """Plain-text tables of the counts."""
    if not rows:
        return "No usage lines found."
    out = []
    sections = [
        ("Views per day", Counter(day for day, _ in rows)),
        ("By page", Counter(f["event"] for _, f in rows)),
        ("By source", Counter(f.get("source", "?") for _, f in rows)),
        ("By network", Counter(f.get("operator", "?") for _, f in rows)),
    ]
    for title, counts in sections:
        out.append(title)
        ordered = sorted(counts.items()) if title == "Views per day" else counts.most_common()
        for key, n in ordered:
            out.append(f"  {key:<20} {n:>7}")
        out.append("")
    searches = sum(1 for _, f in rows if f["event"] == "journey_search")
    out.append(f"Total views {len(rows)}, journey searches {searches}")
    return "\n".join(out)


def main() -> int:
    """Read files named on the command line, or stdin."""
    print(report(parse(fileinput.input(sys.argv[1:]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
