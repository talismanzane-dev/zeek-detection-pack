#!/usr/bin/env python3
"""Derive *candidate* ``labels.json`` entries from a CTU-13 ``.binetflow`` file.

CTU-13 (Garcia et al., "An empirical comparison of botnet detection methods",
Computers & Security 45, 2014) ships, per scenario, a pcap and an Argus
bidirectional-flow file whose ``Label`` column marks flows as Background,
Normal or Botnet (``flow=From-Botnet-V42-TCP-CC6-Plain-HTTP...``). Labels that
contain ``-CC`` denote command-and-control channels.

This tool turns C2-labelled botnet flows into ``c2_beaconing`` ground truth:
flows are grouped by ``(SrcAddr, DstAddr, Dport, Proto)`` into tumbling
windows and every group with at least ``--min-flows`` flows becomes one label.
The output is a **starting point that must be reviewed** — CTU-13 labels
describe hosts and flows, not beaconing per se, and other detectors
(DNS tunneling, DGA, lateral movement) need their own labelled data. See
docs/evaluation.md for the full procedure.

CTU-13 hosts live in the university's public range, so the tool also writes a
``site.yaml`` overlay declaring the internal network (default
``147.32.0.0/16``).

    python tools/ctu13_labels.py --binetflow capture20110810.binetflow \
        --scenario ctu13-42 --out-dir data/ctu13/42
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

DEFAULT_LABEL_RE = r"From-Botnet.*-CC"
TIME_FORMAT = "%Y/%m/%d %H:%M:%S.%f"


@dataclass(frozen=True)
class Flow:
    start: float
    end: float
    proto: str
    src: str
    dst: str
    dport: int
    label: str


def parse_flows(
    rows: Iterable[dict[str, str]], tz: ZoneInfo, label_re: re.Pattern[str]
) -> Iterator[Flow]:
    for row in rows:
        label = (row.get("Label") or "").strip()
        if not label_re.search(label):
            continue
        direction = (row.get("Dir") or "").strip()
        if "->" not in direction:
            continue  # only flows initiated by the source
        try:
            start = datetime.strptime(row["StartTime"].strip(), TIME_FORMAT).replace(tzinfo=tz)
            dport = int(str(row["Dport"]).strip(), 0)
            duration = float(row.get("Dur") or 0.0)
        except (KeyError, ValueError):
            continue
        ts = start.timestamp()
        yield Flow(
            ts,
            ts + duration,
            row["Proto"].strip().lower(),
            row["SrcAddr"].strip(),
            row["DstAddr"].strip(),
            dport,
            label,
        )


def build_labels(
    flows: Iterable[Flow], window: float, min_flows: int, scenario: str
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, int, str, int], list[Flow]] = defaultdict(list)
    for flow in flows:
        bucket = int(flow.start // window)
        groups[(flow.src, flow.dst, flow.dport, flow.proto, bucket)].append(flow)
    labels = []
    for (src, dst, dport, proto, _), members in sorted(groups.items()):
        if len(members) < min_flows:
            continue
        endpoint = f"[{dst}]:{dport}" if ":" in dst else f"{dst}:{dport}"
        names = sorted({m.label for m in members})
        labels.append(
            {
                "detector": "c2_beaconing",
                "src": src,
                "dst": dst,
                "indicator": endpoint,
                "window": [
                    round(min(m.start for m in members), 6),
                    round(max(m.end for m in members), 6),
                ],
                "technique_id": "T1071",
                "note": (
                    f"CTU-13 {scenario}: {len(members)} {proto} flows labelled "
                    f"{', '.join(names)[:200]} "
                    "— candidate label, review before use"
                ),
            }
        )
    return labels


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--binetflow", type=Path, required=True)
    ap.add_argument("--scenario", required=True, help="scenario name recorded in labels.json")
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--label-regex", default=DEFAULT_LABEL_RE)
    ap.add_argument(
        "--timezone",
        default="Europe/Prague",
        help="timezone of binetflow StartTime values (verify against the pcap)",
    )
    ap.add_argument("--window", type=float, default=3600.0)
    ap.add_argument("--min-flows", type=int, default=8)
    ap.add_argument(
        "--internal",
        action="append",
        default=None,
        help="internal CIDR for site.yaml (repeatable; default 147.32.0.0/16)",
    )
    args = ap.parse_args(argv)

    with args.binetflow.open(encoding="utf-8", errors="replace", newline="") as fh:
        flows = list(
            parse_flows(csv.DictReader(fh), ZoneInfo(args.timezone), re.compile(args.label_regex))
        )
    labels = build_labels(flows, args.window, args.min_flows, args.scenario)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "scenario": args.scenario,
        "description": (
            f"Candidate c2_beaconing labels derived from {args.binetflow.name} by "
            f"tools/ctu13_labels.py (label regex {args.label_regex!r}, window {args.window:g}s, "
            f">= {args.min_flows} flows). Review before reporting metrics."
        ),
        "labels": labels,
        "benign": [],
    }
    (args.out_dir / "labels.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    internal = args.internal or ["147.32.0.0/16"]
    site = "site:\n  networks:\n    internal:\n" + "".join(f'      - "{c}"\n' for c in internal)
    (args.out_dir / "site.yaml").write_text(site, encoding="utf-8")
    print(
        f"{len(flows)} matching flows → {len(labels)} candidate labels in {args.out_dir}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
