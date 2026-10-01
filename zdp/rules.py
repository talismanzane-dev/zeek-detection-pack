"""Exported-rule value types shared by analyzers and the exporters.

Analyzers build these from their *live* configuration (``to_sigma()`` /
``to_suricata()``), so exported thresholds can never drift from the Python
thresholds. The exporters only serialize and validate them.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

#: Fidelity tiers (spec §5.3).
TIER_FULL = "full"
TIER_APPROX = "approx"
TIER_COMPANION = "companion"
TIERS = (TIER_FULL, TIER_APPROX, TIER_COMPANION)

#: Namespace for deterministic rule UUIDs. Never change: downstream SIEMs key
#: on these identifiers to update rules in place instead of duplicating them.
RULE_NAMESPACE = uuid.UUID("5b0f6c1e-8a77-5d0e-9d2b-7a2f6f1c3e10")

#: Suricata reserves 1,000,000–1,999,999 for local rules.
SURICATA_SID_BASE = 1_000_000
SURICATA_SID_SPAN = 1_000_000


def rule_uuid(detector: str, signal: str, config_hash: str) -> str:
    """UUIDv5 from detector slug + signal + config hash (spec §5.3)."""
    return str(uuid.uuid5(RULE_NAMESPACE, f"{detector}/{signal}/{config_hash}"))


def suricata_sid(detector: str, signal: str, config_hash: str) -> int:
    """Deterministic SID in the local range, derived from the rule UUID."""
    value = uuid.UUID(rule_uuid(detector, signal, config_hash)).int
    return SURICATA_SID_BASE + value % SURICATA_SID_SPAN


@dataclass(frozen=True)
class SigmaRule:
    """One Sigma document (a detection rule or a v2 correlation rule)."""

    detector: str
    signal: str
    tier: str
    document: dict[str, Any]
    #: Extra documents written to the same file (e.g. a correlation's base rule).
    companions: tuple[dict[str, Any], ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"invalid tier {self.tier!r}")

    @property
    def filename(self) -> str:
        return f"zdp_{self.detector}_{self.signal}.yml"


@dataclass(frozen=True)
class SuricataRule:
    """One Suricata rule line plus provenance."""

    detector: str
    signal: str
    tier: str
    sid: int
    text: str
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"invalid tier {self.tier!r}")
        if "\n" in self.text:
            raise ValueError("Suricata rules must be a single line")


@dataclass(frozen=True)
class ExportSkip:
    """Recorded when a detector (or signal) cannot be expressed in a format."""

    detector: str
    signal: str
    fmt: str
    reason: str
