"""Shared scoring helpers: linear ramps, dispersion statistics, entropy.

Every detector scores with the same weighted-component model
(``confidence = Σ wᵢ·cᵢ``, ``cᵢ ∈ [0, 1]``, ``Σ wᵢ = 1``). The helpers here are
deliberately small and pure so they can be unit-tested against synthetic
metric inputs (e.g. "CV = 0.10 → component = 1.0").
"""

from __future__ import annotations

import itertools
import math
import statistics
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence

#: Scale factor that makes the MAD a consistent estimator of σ for normal data.
MAD_TO_SIGMA = 1.4826

#: Confidence bands for severity (spec §1.2).
SEVERITY_BANDS: tuple[tuple[float, str], ...] = ((0.85, "high"), (0.6, "medium"))
SEVERITIES: tuple[str, ...] = ("low", "medium", "high")

_WEIGHT_TOLERANCE = 1e-6
_VOWELS = frozenset("aeiouy")


def clamp01(value: float) -> float:
    """Clamp ``value`` into ``[0, 1]``; NaN maps to 0."""
    if math.isnan(value):
        return 0.0
    return min(1.0, max(0.0, value))


def ramp(value: float, zero_at: float, one_at: float) -> float:
    """Piecewise-linear mapping of ``value`` onto ``[0, 1]``.

    Returns 0.0 at or beyond ``zero_at``, 1.0 at or beyond ``one_at``, and
    interpolates linearly between them. The direction is inferred from the
    ordering of the two anchors, so the same helper expresses both
    "higher is more suspicious" (entropy: ``zero_at=3.0, one_at=4.0``) and
    "lower is more suspicious" (interval CV: ``zero_at=0.5, one_at=0.12``).
    """
    if zero_at == one_at:
        raise ValueError("ramp anchors must differ")
    if math.isnan(value):
        return 0.0
    return clamp01((value - zero_at) / (one_at - zero_at))


def weighted_score(components: Mapping[str, float], weights: Mapping[str, float]) -> float:
    """Combine component scores with weights that must sum to one.

    Raises ``ValueError`` for missing components, components outside
    ``[0, 1]``, or weights that do not sum to 1 — misconfigured weights
    silently inflating confidence would defeat the auditability goal.
    """
    validate_weights(weights)
    missing = set(weights) - set(components)
    if missing:
        raise ValueError(f"missing score components: {sorted(missing)}")
    total = 0.0
    for name, weight in weights.items():
        component = components[name]
        if not 0.0 <= component <= 1.0:
            raise ValueError(f"component {name!r}={component} outside [0, 1]")
        total += weight * component
    return clamp01(total)


def validate_weights(weights: Mapping[str, float]) -> None:
    """Raise ``ValueError`` unless all weights are non-negative and sum to 1."""
    if not weights:
        raise ValueError("weights must not be empty")
    if any(w < 0 for w in weights.values()):
        raise ValueError(f"weights must be non-negative: {dict(weights)}")
    total = math.fsum(weights.values())
    if abs(total - 1.0) > _WEIGHT_TOLERANCE:
        raise ValueError(f"weights must sum to 1.0, got {total:.6f}: {dict(weights)}")


def severity_for(confidence: float) -> str:
    """Map a confidence in ``[0, 1]`` to ``low`` / ``medium`` / ``high``."""
    for floor, label in SEVERITY_BANDS:
        if confidence >= floor:
            return label
    return "low"


def reduce_severity(severity: str, steps: int = 1) -> str:
    """Lower a severity by ``steps`` bands, never below ``low``."""
    index = SEVERITIES.index(severity)
    return SEVERITIES[max(0, index - steps)]


# --- dispersion statistics --------------------------------------------------


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("median of empty sequence")
    return float(statistics.median(values))


def mad(values: Sequence[float]) -> float:
    """Median absolute deviation (unscaled)."""
    center = median(values)
    return median([abs(v - center) for v in values])


def coefficient_of_variation(values: Sequence[float]) -> float | None:
    """Population σ/μ; ``None`` when undefined (fewer than 2 values or μ = 0)."""
    if len(values) < 2:
        return None
    mean = math.fsum(values) / len(values)
    if mean == 0:
        return None
    return statistics.pstdev(values, mu=mean) / mean


def robust_cv(values: Sequence[float]) -> float | None:
    """MAD-based CV: ``1.4826 · MAD / median``; ``None`` when undefined."""
    if len(values) < 2:
        return None
    center = median(values)
    if center == 0:
        return None
    return MAD_TO_SIGMA * mad(values) / center


def deltas(timestamps: Sequence[float]) -> list[float]:
    """Successive differences of an ascending sequence."""
    return [b - a for a, b in itertools.pairwise(timestamps)]


# --- lexical features -------------------------------------------------------


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0.0 for the empty string)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -math.fsum((n / length) * math.log2(n / length) for n in counts.values())


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isdigit() for ch in text) / len(text)


def longest_consonant_run(text: str) -> int:
    """Longest run of ASCII consonants (``y`` is treated as a vowel)."""
    best = current = 0
    for ch in text.lower():
        if "a" <= ch <= "z" and ch not in _VOWELS:
            current += 1
            best = max(best, current)
        else:
            current = 0
    return best


def mean(values: Iterable[float]) -> float:
    items = list(values)
    if not items:
        raise ValueError("mean of empty sequence")
    return math.fsum(items) / len(items)
