#!/usr/bin/env python3
"""Render the README metrics block from a benchmark ``metrics.json``.

The block between the ``BEGIN GENERATED METRICS`` / ``END GENERATED METRICS``
markers is the only place a metric value may appear in the repository, and
only this tool writes it. Sources:

* ``--metrics PATH`` (default ``metrics/benchmark.json``): a harness output
  for a real dataset, e.g. ``python -m zdp.harness --suite ctu13 ...``.
* If the file does not exist, or its ``suite`` is the synthetic
  ``fixtures`` suite (logic tests, not a benchmark), the block is rendered
  with explicit placeholders instead.

``--check`` exits 1 when the committed README differs from what would be
rendered (used by CI's docs job).

    python tools/render_metrics.py --metrics metrics/benchmark.json
    python tools/render_metrics.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

REPO = Path(__file__).resolve().parents[1]
BEGIN = "<!-- BEGIN GENERATED METRICS (tools/render_metrics.py; do not edit by hand) -->"
END = "<!-- END GENERATED METRICS -->"
DETECTORS = ("c2_beaconing", "dns_tunneling", "dga", "lateral_movement")
NON_BENCHMARK_SUITES = {"fixtures"}
PLACEHOLDER = "PLACEHOLDER: compute from CTU-13 run"


def placeholder_block(reason: str) -> str:
    rows = [
        f"| `{d}` | CTU-13 | {PLACEHOLDER} | {PLACEHOLDER} | {PLACEHOLDER} | {PLACEHOLDER} |"
        for d in DETECTORS
    ]
    return "\n".join(
        [
            "> **No benchmark has been run yet — every value below is a placeholder.**",
            f"> {reason}",
            "> Procedure: [docs/evaluation.md](docs/evaluation.md). Do not replace these cells by",
            "> hand; run the harness on the dataset and re-render this block with",
            "> `tools/render_metrics.py`.",
            "",
            "| Detector | Dataset | Precision | Recall | F1 | False positives |",
            "|---|---|---|---|---|---|",
            *rows,
        ]
    )


def _badge(label: str, value: float, undefined: bool) -> str:
    text = "n%2Fa" if undefined else quote(f"{value:.3f}")
    color = "lightgrey" if undefined else "blue"
    return f"![{label}](https://img.shields.io/badge/{quote(label)}-{text}-{color})"


def metrics_block(metrics: dict[str, Any]) -> str:
    lines = [
        f"Benchmark suite **`{metrics['suite']}`** — zdp `{metrics['framework_version']}`, "
        f"config `{metrics['config_hash']}`, generated `{metrics['generated_at']}`, "
        f"±{metrics['settings']['tolerance_seconds']:g} s matching tolerance, dedup policy "
        f"`{metrics['settings']['dedup_policy']}`.",
        "",
    ]
    overall = metrics["overall"]
    und = set(overall["undefined"])
    lines.append(
        " ".join(
            [
                _badge("precision (micro)", overall["precision"], "precision" in und),
                _badge("recall (micro)", overall["recall"], "recall" in und),
                _badge("F1 (micro)", overall["f1"], "f1" in und),
            ]
        )
    )
    lines += [
        "",
        "| Detector | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, m in metrics["detectors"].items():
        cells = {
            k: "n/a" if k in m["undefined"] else f"{m[k]:.3f}"
            for k in ("precision", "recall", "f1")
        }
        lines.append(
            f"| `{name}` | {m['tp']} | {m['fp']} | {m['fn']} | {cells['precision']} | "
            f"{cells['recall']} | {cells['f1']} |"
        )
    return "\n".join(lines)


def render(metrics_path: Path) -> str:
    if not metrics_path.is_file():
        body = placeholder_block(f"No benchmark metrics file found at `{metrics_path.name}`.")
    else:
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        if metrics.get("suite") in NON_BENCHMARK_SUITES:
            body = placeholder_block(
                f"`{metrics_path.name}` is from the synthetic `{metrics['suite']}` suite, which "
                "tests detector logic and is not a performance benchmark."
            )
        else:
            body = metrics_block(metrics)
    return f"{BEGIN}\n{body}\n{END}"


def splice(readme: str, block: str) -> str:
    start, end = readme.find(BEGIN), readme.find(END)
    if start == -1 or end == -1 or end < start:
        raise ValueError("README is missing the generated-metrics markers")
    return readme[:start] + block + readme[end + len(END) :]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--metrics", type=Path, default=REPO / "metrics" / "benchmark.json")
    ap.add_argument("--readme", type=Path, default=REPO / "README.md")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    current = args.readme.read_text(encoding="utf-8")
    updated = splice(current, render(args.metrics))
    if args.check:
        if updated != current:
            print("README metrics block is stale: run tools/render_metrics.py", file=sys.stderr)
            return 1
        print("README metrics block is up to date")
        return 0
    if updated != current:
        args.readme.write_text(updated, encoding="utf-8")
        print(f"updated {args.readme}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
