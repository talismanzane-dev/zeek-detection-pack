"""Character-bigram language model for domain labels (used by the DGA detector).

The model is a first-order Markov chain over ``[a-z0-9-]`` with start (``^``)
and end (``$``) markers, trained on Tranco second-level labels by
``tools/train_bigrams.py`` and shipped as ``zdp/data/bigram_freq.json``.

The score calibration points (where the bigram component is 0 and where it
is 1) are *derived by the training tool from the bundled table* and stored
alongside it; they are never hard-coded here. ``calibrate_random_baseline``
is exposed so tests can re-derive the random-string anchor from the table
and confirm the shipped values were produced from it.
"""

from __future__ import annotations

import itertools
import json
import math
import random
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_PATH = Path(__file__).resolve().parent / "data" / "bigram_freq.json"
START, END = "^", "$"
LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"


@dataclass(frozen=True)
class BigramModel:
    logprob: Mapping[str, Mapping[str, float]]
    unknown_logprob: float
    calibration: Mapping[str, Any]
    provenance: Mapping[str, Any]

    @classmethod
    def load(cls, path: Path = DATA_PATH) -> BigramModel:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("schema_version") != 1:
            raise ValueError(f"unsupported bigram table schema: {data.get('schema_version')!r}")
        calibration = data["calibration"]
        for key in ("zero_at", "one_at"):
            if not isinstance(calibration.get(key), (int, float)):
                raise ValueError(f"bigram table is missing calibration.{key}")
        if not calibration["zero_at"] > calibration["one_at"]:
            raise ValueError("bigram calibration must satisfy zero_at > one_at")
        return cls(
            logprob=data["logprob"],
            unknown_logprob=float(data["unknown_logprob"]),
            calibration=calibration,
            provenance=data.get("provenance", {}),
        )

    def transition(self, prev: str, nxt: str) -> float:
        row = self.logprob.get(prev)
        if row is None:
            return self.unknown_logprob
        return float(row.get(nxt, self.unknown_logprob))

    def mean_logprob(self, label: str) -> float:
        """Mean natural-log transition probability across ``^label$``."""
        chars = [START, *label.lower(), END]
        total = math.fsum(self.transition(a, b) for a, b in itertools.pairwise(chars))
        return total / (len(chars) - 1)

    @property
    def zero_at(self) -> float:
        return float(self.calibration["zero_at"])

    @property
    def one_at(self) -> float:
        return float(self.calibration["one_at"])


def random_labels(
    lengths: Mapping[int, int] | Sequence[tuple[int, int]], count: int, seed: int
) -> list[str]:
    """Uniform random ``[a-z0-9]`` labels with lengths drawn from a histogram."""
    items = sorted(dict(lengths).items()) if isinstance(lengths, Mapping) else sorted(lengths)
    rng = random.Random(seed)
    population = [int(length) for length, _ in items]
    weights = [int(n) for _, n in items]
    alphabet = LABEL_ALPHABET[:-1]  # no hyphen: DGA output is overwhelmingly alnum
    drawn = rng.choices(population, weights=weights, k=count)
    return ["".join(rng.choice(alphabet) for _ in range(n)) for n in drawn]


def percentile(values: Sequence[float], pct: float) -> float:
    """Inclusive-method percentile (deterministic, no numpy dependency)."""
    if not values:
        raise ValueError("percentile of empty sequence")
    if len(values) == 1:
        return float(values[0])
    cuts = statistics.quantiles(sorted(values), n=1000, method="inclusive")
    index = min(len(cuts) - 1, max(0, round(pct * 10) - 1))
    return float(cuts[index])


def calibrate_random_baseline(model: BigramModel) -> float:
    """Re-derive the ``one_at`` anchor from the table's stored procedure."""
    cal = model.calibration
    labels = random_labels(
        {int(k): int(v) for k, v in cal["length_histogram"].items()},
        int(cal["random_samples"]),
        int(cal["random_seed"]),
    )
    scores = [model.mean_logprob(label) for label in labels]
    return round(percentile(scores, float(cal["random_percentile"])), 4)


@lru_cache(maxsize=2)
def get_model(path: Path = DATA_PATH) -> BigramModel:
    return BigramModel.load(path)
