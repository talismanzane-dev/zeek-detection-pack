#!/usr/bin/env python3
"""Regenerate the Tranco section of ``config/allowlists/domains.txt``.

Only the block between the ``BEGIN TRANCO`` / ``END TRANCO`` markers is
rewritten; local additions elsewhere in the file are preserved. Entries are
reduced to registered domains with the pinned PSL (private suffixes
included) and de-duplicated, preserving rank order.

Usage::

    python tools/build_domain_allowlist.py --tranco top-1m.csv --list-id 8PXYV --top 1000
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from zdp.psl import DomainParser  # noqa: E402

BEGIN = "# --- BEGIN TRANCO"
END = "# --- END TRANCO"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--tranco", type=Path, required=True)
    ap.add_argument("--list-id", required=True)
    ap.add_argument("--top", type=int, default=1000)
    ap.add_argument("--file", type=Path, default=REPO / "config" / "allowlists" / "domains.txt")
    args = ap.parse_args(argv)

    parser = DomainParser()
    domains: dict[str, None] = {}
    with args.tranco.open(encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 2 or int(row[0]) > args.top:
                break
            registered = parser.registered_domain(row[1])
            if registered:
                domains.setdefault(registered, None)

    block = [
        f"{BEGIN} (list {args.list_id}, top {args.top}, "
        f"https://tranco-list.eu/list/{args.list_id}/1000000; regenerate with "
        "tools/build_domain_allowlist.py — do not hand-edit) ---",
        *domains,
        f"{END} ---",
    ]
    text = args.file.read_text(encoding="utf-8") if args.file.exists() else ""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.startswith(BEGIN))
        end = next(i for i, line in enumerate(lines) if line.startswith(END))
        lines[start : end + 1] = block
    except StopIteration:
        lines = [*lines, "", *block] if lines else block
    args.file.parent.mkdir(parents=True, exist_ok=True)
    args.file.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    print(f"wrote {len(domains)} registered domains to {args.file}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
