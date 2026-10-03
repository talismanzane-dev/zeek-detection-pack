#!/usr/bin/env python3
"""Fail if documentation contains literal detection-metric values.

Metrics (precision, recall, F1, FP/TP rates, accuracy …) may only exist as
runtime harness output or inside the README block written by
``tools/render_metrics.py``. This lint scans tracked Markdown files and
flags:

* a metric keyword followed closely by a number that looks like a rate
  (``0.93``, ``.9``, ``1.0``, ``93 %``) or the reverse order;
* numeric cells in Markdown table columns whose header names a metric.

Lines containing ``PLACEHOLDER``, ``TODO: measured`` or the marker
``metric-lint: allow`` are exempt, as is everything between the generated
block markers.

    python tools/check_no_hardcoded_metrics.py            # scan tracked *.md
    python tools/check_no_hardcoded_metrics.py FILE ...   # scan given files
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BEGIN = "<!-- BEGIN GENERATED METRICS"
END = "<!-- END GENERATED METRICS -->"
EXEMPT = ("PLACEHOLDER", "TODO: measured", "metric-lint: allow")

KEYWORDS = (
    r"precision|recall|f1(?:[- ]score)?|f-score|f-measure|accuracy|auc|"
    r"tpr|fpr|true[- ]positive[- ]rate|false[- ]positive[- ]rate|fp[- ]rate|"
    r"false[- ]alarm[- ]rate|detection[- ]rate|hit[- ]rate"
)
RATE = r"(?<![\w.])(?:0?\.\d+|1\.0+|\d{1,3}(?:\.\d+)?\s?%)(?![0-9A-Za-z_])"
FORWARD = re.compile(rf"\b(?:{KEYWORDS})\b[^\n0-9]{{0,30}}?{RATE}", re.IGNORECASE)
BACKWARD = re.compile(rf"{RATE}\s*(?:\w+\s+){{0,2}}(?:{KEYWORDS})\b", re.IGNORECASE)
HEADER_KEY = re.compile(rf"\b(?:{KEYWORDS})\b", re.IGNORECASE)
CELL_NUMBER = re.compile(rf"^\s*\**{RATE}\**\s*$")


def tracked_markdown() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.md"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return [REPO / line for line in out.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):
        skip = {".venv", "node_modules", ".git"}
        return [p for p in REPO.rglob("*.md") if not skip & set(p.parts)]


def scan_text(text: str) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    inside = False
    table_metric_cols: set[int] | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith(BEGIN):
            inside = True
            continue
        if line.strip().startswith(END):
            inside = False
            continue
        if inside or any(marker in line for marker in EXEMPT):
            table_metric_cols = table_metric_cols if line.lstrip().startswith("|") else None
            continue
        stripped = line.strip()
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if table_metric_cols is None:
                table_metric_cols = {i for i, c in enumerate(cells) if HEADER_KEY.search(c)}
            elif not all(set(c) <= set("-: ") for c in cells):
                for i in table_metric_cols:
                    if i < len(cells) and CELL_NUMBER.match(cells[i]):
                        findings.append((lineno, f"metric literal in table cell: {cells[i]!r}"))
        else:
            table_metric_cols = None
        for pattern in (FORWARD, BACKWARD):
            for m in pattern.finditer(line):
                findings.append((lineno, f"metric literal: {m.group(0).strip()!r}"))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    files = [Path(a) for a in args] if args else tracked_markdown()
    total = 0
    for path in sorted(files):
        if not path.is_file():
            continue
        for lineno, message in scan_text(path.read_text(encoding="utf-8")):
            rel = path.relative_to(REPO) if path.is_relative_to(REPO) else path
            print(f"{rel}:{lineno}: {message}")
            total += 1
    if total:
        print(
            f"\n{total} hard-coded metric value(s) found. Metrics must come from the harness; "
            "use 'PLACEHOLDER: …' until a real run exists.",
            file=sys.stderr,
        )
        return 1
    print(f"no hard-coded metrics in {len(files)} markdown file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
