"""Core data model: ``Detection``, ``LogWindow`` and ``AnalyzerConfig``."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, fields
from typing import Any

from zdp.policy import BusinessHours, DomainPolicy, NetworkPolicy
from zdp.scoring import SEVERITIES, clamp01, severity_for
from zdp.state import AnalyzerState

#: A normalized Zeek record: dotted Zeek field names → typed Python values
#: (epoch floats, ints, bools, compressed IP strings, lists; ``None`` = unset).
Record = dict[str, Any]

#: Contributing UIDs are capped so a single noisy detection cannot bloat output.
MAX_UIDS = 50

_EVIDENCE_FLOAT_DIGITS = 6


@dataclass(frozen=True)
class Detection:
    """One analyzer finding. Field order is the stable JSON serialization order."""

    ts: float
    last_ts: float
    detector: str
    src: str
    dst: str | None
    indicator: str
    confidence: float
    severity: str
    technique_id: str
    tactic: str
    evidence: dict[str, Any]
    uids: list[str]

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence {self.confidence} outside [0, 1]")
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")
        if self.last_ts < self.ts:
            raise ValueError("last_ts must be >= ts")
        if len(self.uids) > MAX_UIDS:
            raise ValueError(f"at most {MAX_UIDS} uids allowed")

    @classmethod
    def build(
        cls,
        *,
        ts: float,
        last_ts: float,
        detector: str,
        src: str,
        dst: str | None,
        indicator: str,
        confidence: float,
        technique_id: str,
        tactic: str,
        evidence: Mapping[str, Any],
        uids: Iterable[str | None],
        severity: str | None = None,
    ) -> Detection:
        """Construct a detection, deriving severity and normalizing payloads."""
        conf = round(clamp01(confidence), 4)
        unique: list[str] = []
        seen: set[str] = set()
        for uid in uids:
            if uid and uid not in seen:
                seen.add(uid)
                unique.append(uid)
                if len(unique) == MAX_UIDS:
                    break
        return cls(
            ts=float(ts),
            last_ts=float(last_ts),
            detector=detector,
            src=src,
            dst=dst,
            indicator=indicator,
            confidence=conf,
            severity=severity or severity_for(conf),
            technique_id=technique_id,
            tactic=tactic,
            evidence=jsonable(dict(evidence)),
            uids=unique,
        )

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Detection:
        return cls(
            ts=float(data["ts"]),
            last_ts=float(data["last_ts"]),
            detector=str(data["detector"]),
            src=str(data["src"]),
            dst=None if data.get("dst") is None else str(data["dst"]),
            indicator=str(data["indicator"]),
            confidence=float(data["confidence"]),
            severity=str(data["severity"]),
            technique_id=str(data["technique_id"]),
            tactic=str(data["tactic"]),
            evidence=dict(data.get("evidence") or {}),
            uids=[str(u) for u in data.get("uids") or ()],
        )

    def sort_key(self) -> tuple[float, str, str, str]:
        return (self.ts, self.detector, self.src, self.indicator)


def jsonable(value: Any) -> Any:
    """Recursively convert to JSON-safe, deterministic structures.

    Mapping keys are sorted, sets become sorted lists, tuples become lists,
    floats are rounded and non-finite floats become ``None``.
    """
    if isinstance(value, Mapping):
        return {str(k): jsonable(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (set, frozenset)):
        return [jsonable(v) for v in sorted(value, key=repr)]
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return round(value, _EVIDENCE_FLOAT_DIGITS)
    return str(value)


@dataclass(frozen=True)
class LogWindow:
    """A half-open time window ``[start, end)`` of normalized, ts-sorted records.

    Analyzers only iterate records; they never index into them. This keeps the
    interface compatible with a future streaming adapter.
    """

    start: float
    end: float
    logs: Mapping[str, Sequence[Record]] = field(default_factory=dict)

    def records(self, log_type: str) -> Iterator[Record]:
        return iter(self.logs.get(log_type, ()))

    def has(self, log_type: str) -> bool:
        return bool(self.logs.get(log_type))

    def count(self, log_type: str) -> int:
        return len(self.logs.get(log_type, ()))

    @property
    def duration(self) -> float:
        return self.end - self.start


@dataclass(frozen=True)
class AnalyzerConfig:
    """Everything an analyzer needs: its parameters plus shared site policy."""

    name: str
    params: Mapping[str, Any]
    networks: NetworkPolicy
    domains: DomainPolicy
    schedule: BusinessHours
    include_psl_private_domains: bool = True
    state: AnalyzerState | None = None
    config_hash: str = ""

    def param(self, key: str) -> Any:
        try:
            return self.params[key]
        except KeyError as exc:
            raise KeyError(f"{self.name}: missing parameter {key!r}") from exc

    def float_param(self, key: str) -> float:
        return float(self.param(key))

    def int_param(self, key: str) -> int:
        return int(self.param(key))

    def section(self, key: str) -> Mapping[str, Any]:
        value = self.param(key)
        if not isinstance(value, Mapping):
            raise TypeError(f"{self.name}: parameter {key!r} must be a mapping")
        return value

    @property
    def min_confidence(self) -> float:
        return self.float_param("min_confidence")

    @property
    def window_seconds(self) -> int:
        return self.int_param("window_seconds")

    @property
    def window_overlap(self) -> float:
        return float(self.params.get("window_overlap", 0.0))

    def is_internal(self, ip: str) -> bool:
        return self.networks.is_internal(ip)
