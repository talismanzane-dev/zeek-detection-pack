#!/usr/bin/env python3
"""Rebuild ``zdp/data/bigram_freq.json`` from a Tranco top-sites list.

Procedure (documented in docs/detectors.md §DGA):

1. Take the top ``--top`` entries of a Tranco CSV (``rank,domain``).
2. Reduce each to its second-level label with the pinned Public Suffix List
   (private suffixes included), drop IDNs (``xn--``) and labels with
   characters outside ``[a-z0-9-]``, and de-duplicate (so ``google.com`` and
   ``google.de`` contribute one ``google``).
3. Count transitions over ``^label$`` and convert to natural-log conditional
   probabilities with add-k smoothing.
4. Calibrate the DGA bigram component from the table itself:
   ``zero_at`` = the ``--benign-percentile`` of mean log-probabilities over
   training labels of at least ``--min-length`` characters, and ``one_at`` =
   the ``--random-percentile`` over seeded uniform random labels whose
   lengths follow the same length histogram. Both anchors are written into
   the JSON next to the table so the scorer never hard-codes them.

Usage::

    python tools/train_bigrams.py --tranco top-1m.csv --list-id 8PXYV \
        --out zdp/data/bigram_freq.json
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from zdp.lexical import (  # noqa: E402
    END,
    LABEL_ALPHABET,
    START,
    BigramModel,
    percentile,
    random_labels,
)
from zdp.psl import DomainParser  # noqa: E402

PERCENTILES = (1, 5, 10, 25, 50, 75, 90, 95, 99)


def load_labels(path: Path, top: int, parser: DomainParser) -> list[str]:
    allowed = set(LABEL_ALPHABET)
    labels: dict[str, None] = {}
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) < 2:
                continue
            if int(row[0]) > top:
                break
            sld = parser.split(row[1]).sld
            if not sld or sld.startswith("xn--") or not set(sld) <= allowed:
                continue
            labels.setdefault(sld, None)
    return list(labels)


def train(labels: list[str], k: float) -> tuple[dict[str, dict[str, float]], float]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for label in labels:
        chars = [START, *label, END]
        for a, b in itertools.pairwise(chars):
            counts[a][b] += 1
    prev_symbols = [START, *LABEL_ALPHABET]
    next_symbols = [*LABEL_ALPHABET, END]
    vocab = len(next_symbols)
    table: dict[str, dict[str, float]] = {}
    for a in prev_symbols:
        row = counts.get(a, Counter())
        total = sum(row.values())
        table[a] = {
            b: round(math.log((row.get(b, 0) + k) / (total + k * vocab)), 4) for b in next_symbols
        }
    unknown = min(v for row in table.values() for v in row.values())
    return table, unknown


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--tranco", type=Path, required=True, help="Tranco CSV (rank,domain)")
    ap.add_argument("--list-id", required=True, help="Tranco list ID, recorded for provenance")
    ap.add_argument("--top", type=int, default=100_000)
    ap.add_argument("--smoothing", type=float, default=1.0, help="add-k smoothing constant")
    ap.add_argument("--min-length", type=int, default=6)
    ap.add_argument("--benign-percentile", type=float, default=10.0)
    ap.add_argument("--random-percentile", type=float, default=50.0)
    ap.add_argument("--random-samples", type=int, default=20_000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--out", type=Path, default=REPO / "zdp" / "data" / "bigram_freq.json")
    args = ap.parse_args(argv)

    parser = DomainParser()
    labels = load_labels(args.tranco, args.top, parser)
    if len(labels) < 1000:
        print(f"refusing to train on only {len(labels)} labels", file=sys.stderr)
        return 1
    table, unknown = train(labels, args.smoothing)

    provisional = BigramModel(
        logprob=table,
        unknown_logprob=unknown,
        calibration={"zero_at": 0.0, "one_at": -1.0},
        provenance={},
    )
    long_labels = [lbl for lbl in labels if len(lbl) >= args.min_length]
    benign_scores = [provisional.mean_logprob(lbl) for lbl in long_labels]
    histogram = Counter(min(len(lbl), 63) for lbl in long_labels)
    randoms = random_labels(histogram, args.random_samples, args.seed)
    random_scores = [provisional.mean_logprob(lbl) for lbl in randoms]

    zero_at = round(percentile(benign_scores, args.benign_percentile), 4)
    one_at = round(percentile(random_scores, args.random_percentile), 4)
    if not zero_at > one_at:
        print(
            f"calibration failed: benign p{args.benign_percentile} ({zero_at}) is not above "
            f"random p{args.random_percentile} ({one_at}); the table does not separate the "
            "classes — inspect the training data",
            file=sys.stderr,
        )
        return 1

    payload = {
        "schema_version": 1,
        "provenance": {
            "source": "Tranco top sites list",
            "tranco_list_id": args.list_id,
            "tranco_permalink": f"https://tranco-list.eu/list/{args.list_id}/1000000",
            "tranco_citation": (
                "Le Pochat et al., 'Tranco: A Research-Oriented Top Sites Ranking Hardened "
                "Against Manipulation', NDSS 2019"
            ),
            "top_n": args.top,
            "unique_labels": len(labels),
            "psl_version": parser.version(),
            "psl_private_domains": True,
            "smoothing": f"add-k, k={args.smoothing}",
            "log_base": "e",
            "generated_by": "tools/train_bigrams.py",
        },
        "alphabet": LABEL_ALPHABET,
        "markers": {"start": START, "end": END},
        "unknown_logprob": unknown,
        "calibration": {
            "method": (
                "zero_at = benign percentile of mean log-prob over training labels "
                f">= {args.min_length} chars; one_at = random percentile over seeded "
                "uniform [a-z0-9] labels drawn with the same length histogram"
            ),
            "zero_at": zero_at,
            "one_at": one_at,
            "min_length": args.min_length,
            "benign_percentile": args.benign_percentile,
            "random_percentile": args.random_percentile,
            "random_samples": args.random_samples,
            "random_seed": args.seed,
            "length_histogram": {str(k): v for k, v in sorted(histogram.items())},
            "benign_distribution": {
                f"p{p}": round(percentile(benign_scores, p), 4) for p in PERCENTILES
            },
            "random_distribution": {
                f"p{p}": round(percentile(random_scores, p), 4) for p in PERCENTILES
            },
        },
        "logprob": table,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(
        f"wrote {args.out}: {len(labels)} labels, zero_at={zero_at}, one_at={one_at}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
