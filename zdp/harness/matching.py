"""Detection ↔ label matching (spec §4.3) and metric computation (spec §4.4).

A detection matches a label iff the detector and source agree, any ``dst`` /
``indicator`` the label specifies agrees (indicators case-insensitively and,
for domains, at the registered-domain level), and the detection's
``[ts, last_ts]`` overlaps the label window widened by the tolerance.

Assignment is one-to-one and greedy: detections are visited in descending
confidence and each claims the earliest-starting unclaimed label it matches.
A detection whose only matches are already claimed is a *duplicate*: ignored
by default, or counted as a false positive under ``dedup_policy="fp"``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from zdp.harness.labels import Label
from zdp.models import Detection
from zdp.psl import DomainParser, get_parser

DEFAULT_TOLERANCE = 120.0
DEDUP_POLICIES = ("ignore", "fp")

_DOMAIN_RE = re.compile(r"^(?=.*[a-z])[a-z0-9_-]+(\.[a-z0-9_-]+)+$")


@dataclass
class MatchResult:
    true_positives: list[tuple[Detection, Label]] = field(default_factory=list)
    false_positives: list[Detection] = field(default_factory=list)
    false_negatives: list[Label] = field(default_factory=list)
    duplicates: list[tuple[Detection, Label]] = field(default_factory=list)

    def counts(self) -> Counts:
        return Counts(
            tp=len(self.true_positives),
            fp=len(self.false_positives),
            fn=len(self.false_negatives),
            duplicates=len(self.duplicates),
        )


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    duplicates: int = 0

    def __add__(self, other: Counts) -> Counts:
        return Counts(
            self.tp + other.tp,
            self.fp + other.fp,
            self.fn + other.fn,
            self.duplicates + other.duplicates,
        )

    def metrics(self) -> dict[str, Any]:
        """Precision / recall / F1; zero denominators yield 0.0 and are flagged."""
        undefined: list[str] = []
        if self.tp + self.fp:
            precision = self.tp / (self.tp + self.fp)
        else:
            precision = 0.0
            undefined.append("precision")
        if self.tp + self.fn:
            recall = self.tp / (self.tp + self.fn)
        else:
            recall = 0.0
            undefined.append("recall")
        if precision + recall:
            f1 = 2 * precision * recall / (precision + recall)
        else:
            f1 = 0.0
            undefined.append("f1")
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "duplicates": self.duplicates,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "undefined": undefined,
        }


def _looks_like_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def indicator_matches(detected: str, labeled: str, parser: DomainParser | None = None) -> bool:
    a, b = detected.strip().lower().rstrip("."), labeled.strip().lower().rstrip(".")
    if a == b:
        return True
    if _looks_like_domain(a) and _looks_like_domain(b):
        parser = parser or get_parser()
        ra, rb = parser.registered_domain(a), parser.registered_domain(b)
        return ra is not None and ra == rb
    return False


def detection_matches(
    det: Detection,
    label: Label,
    tolerance: float = DEFAULT_TOLERANCE,
    parser: DomainParser | None = None,
) -> bool:
    if det.detector != label.detector or det.src != label.src:
        return False
    if label.dst is not None and det.dst != label.dst:
        return False
    if label.indicator is not None and not indicator_matches(
        det.indicator, label.indicator, parser
    ):
        return False
    start, end = label.window
    return det.ts <= end + tolerance and det.last_ts >= start - tolerance


def match(
    detections: Iterable[Detection],
    labels: Sequence[Label],
    *,
    tolerance: float = DEFAULT_TOLERANCE,
    dedup_policy: str = "ignore",
    parser: DomainParser | None = None,
) -> MatchResult:
    if dedup_policy not in DEDUP_POLICIES:
        raise ValueError(f"dedup_policy must be one of {DEDUP_POLICIES}")
    ordered = sorted(
        detections, key=lambda d: (-d.confidence, d.ts, d.detector, d.src, d.indicator)
    )
    label_order = sorted(range(len(labels)), key=lambda i: (labels[i].window[0], i))
    claimed: set[int] = set()
    result = MatchResult()
    for det in ordered:
        hits = [i for i in label_order if detection_matches(det, labels[i], tolerance, parser)]
        free = [i for i in hits if i not in claimed]
        if free:
            claimed.add(free[0])
            result.true_positives.append((det, labels[free[0]]))
        elif hits:
            if dedup_policy == "fp":
                result.false_positives.append(det)
            else:
                result.duplicates.append((det, labels[hits[0]]))
        else:
            result.false_positives.append(det)
    result.false_negatives = [labels[i] for i in label_order if i not in claimed]
    return result
