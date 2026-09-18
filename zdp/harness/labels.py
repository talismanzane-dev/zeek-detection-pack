"""``labels.json`` schema (spec §4.2) and validation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from zdp.policy import normalize_ip, parse_ip

SCHEMA_VERSION = 1


class LabelError(ValueError):
    """Raised for a malformed labels file; the message names the offending entry."""


@dataclass(frozen=True)
class Label:
    """One ground-truth positive event."""

    detector: str
    src: str
    window: tuple[float, float]
    dst: str | None = None
    indicator: str | None = None
    technique_id: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"detector": self.detector, "src": self.src}
        if self.dst is not None:
            out["dst"] = self.dst
        if self.indicator is not None:
            out["indicator"] = self.indicator
        out["window"] = list(self.window)
        if self.technique_id:
            out["technique_id"] = self.technique_id
        if self.note:
            out["note"] = self.note
        return out


@dataclass(frozen=True)
class LabelSet:
    scenario: str
    labels: tuple[Label, ...]
    benign: tuple[Mapping[str, Any], ...]
    description: str = ""

    @property
    def is_pure_negative(self) -> bool:
        return not self.labels


def _ip(value: Any, where: str) -> str:
    if not isinstance(value, str) or parse_ip(value) is None:
        raise LabelError(f"{where}: {value!r} is not a valid IP address")
    return normalize_ip(value)


def parse_label(raw: Any, where: str) -> Label:
    if not isinstance(raw, Mapping):
        raise LabelError(f"{where}: label must be an object")
    for key in ("detector", "src", "window"):
        if key not in raw:
            raise LabelError(f"{where}: missing required field {key!r}")
    detector = raw["detector"]
    if not isinstance(detector, str) or not detector:
        raise LabelError(f"{where}: detector must be a non-empty string")
    window = raw["window"]
    if (
        not isinstance(window, (list, tuple))
        or len(window) != 2
        or not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in window)
    ):
        raise LabelError(f"{where}: window must be [start, end] epoch seconds")
    start, end = float(window[0]), float(window[1])
    if end < start:
        raise LabelError(f"{where}: window end precedes start")
    indicator = raw.get("indicator")
    if indicator is not None and (not isinstance(indicator, str) or not indicator):
        raise LabelError(f"{where}: indicator must be a non-empty string")
    unknown = set(raw) - {"detector", "src", "dst", "indicator", "window", "technique_id", "note"}
    if unknown:
        raise LabelError(f"{where}: unknown fields {sorted(unknown)}")
    return Label(
        detector=detector,
        src=_ip(raw["src"], f"{where}.src"),
        dst=None if raw.get("dst") is None else _ip(raw["dst"], f"{where}.dst"),
        indicator=indicator,
        window=(start, end),
        technique_id=raw.get("technique_id"),
        note=str(raw.get("note") or ""),
    )


def parse_labels(data: Any, scenario: str = "") -> LabelSet:
    if not isinstance(data, Mapping):
        raise LabelError(f"{scenario}: labels file must be a JSON object")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise LabelError(f"{scenario}: unsupported schema_version {version!r}")
    raw_labels = data.get("labels")
    if not isinstance(raw_labels, list):
        raise LabelError(f"{scenario}: 'labels' must be a list (empty for pure-negative)")
    benign = data.get("benign") or []
    if not isinstance(benign, list) or not all(isinstance(b, Mapping) for b in benign):
        raise LabelError(f"{scenario}: 'benign' must be a list of objects")
    labels = tuple(parse_label(r, f"{scenario}.labels[{i}]") for i, r in enumerate(raw_labels))
    return LabelSet(
        scenario=str(data.get("scenario") or scenario),
        labels=labels,
        benign=tuple(benign),
        description=str(data.get("description") or ""),
    )


def load_labels(path: str | Path) -> LabelSet:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LabelError(f"{path}: invalid JSON: {exc}") from exc
    return parse_labels(data, scenario=path.parent.name)
