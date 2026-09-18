"""Labeled-fixture test harness (spec §4)."""

from zdp.harness.labels import Label, LabelError, LabelSet, load_labels
from zdp.harness.matching import Counts, MatchResult, match
from zdp.harness.runner import run_harness

__all__ = [
    "Counts",
    "Label",
    "LabelError",
    "LabelSet",
    "MatchResult",
    "load_labels",
    "match",
    "run_harness",
]
