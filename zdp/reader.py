"""Zeek log reading and normalization (TSV or JSON, auto-detected).

Format detection sniffs the first non-blank line: Zeek ASCII logs always begin
with a ``#separator`` header, JSON logs with ``{``. Gzip-compressed logs
(``*.log.gz``) are read transparently.

Normalization contract (relied on by every analyzer):

* field names are Zeek's dotted names (``id.orig_h``); nested JSON objects
  are flattened to the same form;
* unset fields (``-`` in TSV, missing keys in JSON) are ``None``;
* ``time``/``interval``/``double`` → ``float`` epoch seconds, ``count``/
  ``int``/``port`` → ``int``, ``bool`` → ``bool``, containers → ``list``;
* addresses are canonical compressed strings (IPv6 lower-case, ``::``);
* DNS ``query`` is lower-cased with any trailing dot removed;
* records are sorted by ``ts``; exact duplicates (and repeated ``conn`` uids,
  e.g. from merged sensor output) are dropped.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from zdp.models import Record
from zdp.policy import normalize_ip

LOG = logging.getLogger(__name__)

#: Address-typed fields normalized in JSON logs (TSV logs carry ``#types``).
_JSON_ADDR_FIELDS = frozenset({"id.orig_h", "id.resp_h", "src", "dst", "host", "assigned_addr"})
_JSON_TIME_FIELDS = frozenset(
    {"ts", "times.modified", "times.accessed", "times.created", "times.changed"}
)
# Zeek's ASCII writer escapes backslashes as ``\\`` and separators /
# non-printables as ``\xHH`` (verified against Zeek 9 output).
_TSV_ESCAPE = re.compile(r"\\(?:(\\)|x([0-9a-fA-F]{2}))")


@dataclass
class ReadStats:
    """Per-log-type counters surfaced in runner output."""

    files: int = 0
    lines: int = 0
    records: int = 0
    malformed: int = 0
    duplicates: int = 0
    dropped: int = 0
    formats: set[str] = field(default_factory=set)

    def merge(self, other: ReadStats) -> None:
        self.files += other.files
        self.lines += other.lines
        self.records += other.records
        self.malformed += other.malformed
        self.duplicates += other.duplicates
        self.dropped += other.dropped
        self.formats |= other.formats

    def as_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "lines": self.lines,
            "records": self.records,
            "malformed": self.malformed,
            "duplicates": self.duplicates,
            "dropped": self.dropped,
            "formats": sorted(self.formats),
        }


# --- discovery ------------------------------------------------------------------


def discover_logs(log_dir: str | Path, log_type: str) -> list[Path]:
    """Find ``<type>.log``, rotated ``<type>.<stamp>.log`` and ``.gz`` variants.

    The search is recursive so a directory of per-sensor or per-pcap
    sub-directories is treated as one merged dataset.
    """
    root = Path(log_dir)
    if root.is_file():
        return [root] if _log_type_of(root) == log_type else []
    patterns = (
        f"{log_type}.log",
        f"{log_type}.log.gz",
        f"{log_type}.*.log",
        f"{log_type}.*.log.gz",
    )
    found: set[Path] = set()
    for pattern in patterns:
        found.update(p for p in root.rglob(pattern) if p.is_file())
    return sorted(found)


def _log_type_of(path: Path) -> str:
    return path.name.split(".", 1)[0]


def present_log_types(log_dir: str | Path, candidates: Iterable[str]) -> set[str]:
    return {t for t in candidates if discover_logs(log_dir, t)}


# --- parsing ----------------------------------------------------------------------


def _open_text(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace", newline="\n")


def detect_format(first_line: str) -> str:
    stripped = first_line.lstrip("﻿").strip()
    if stripped.startswith("#separator") or stripped.startswith("#"):
        return "tsv"
    if stripped.startswith("{"):
        return "json"
    raise ValueError(f"unrecognized Zeek log format (first line: {stripped[:60]!r})")


def unescape_zeek(value: str) -> str:
    """Decode Zeek TSV string escaping: ``\\\\`` → ``\\`` and ``\\xHH`` → char."""
    if "\\" not in value:
        return value
    return _TSV_ESCAPE.sub(lambda m: "\\" if m.group(1) else chr(int(m.group(2), 16)), value)


@dataclass
class _TSVHeader:
    separator: str = "\t"
    set_separator: str = ","
    empty_field: str = "(empty)"
    unset_field: str = "-"
    path: str = ""
    fields: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)


def _scalar_converter(ztype: str) -> Callable[[str], Any]:
    if ztype in ("time", "interval", "double"):
        return float
    if ztype in ("count", "int", "port"):
        return int
    if ztype == "bool":
        return lambda v: v == "T"
    if ztype == "addr":
        return normalize_ip
    return unescape_zeek


def _converter(ztype: str, header: _TSVHeader) -> Callable[[str], Any]:
    for prefix in ("set[", "vector[", "table["):
        if ztype.startswith(prefix) and ztype.endswith("]"):
            inner = _scalar_converter(ztype[len(prefix) : -1])

            def convert_container(value: str, _inner: Callable[[str], Any] = inner) -> Any:
                if value == header.empty_field:
                    return []
                return [_inner(v) for v in value.split(header.set_separator)]

            return convert_container
    scalar = _scalar_converter(ztype)
    if ztype in ("string", "enum", "pattern", ""):

        def convert_string(value: str) -> Any:
            return "" if value == header.empty_field else scalar(value)

        return convert_string
    return scalar


def _parse_header_line(line: str, header: _TSVHeader) -> None:
    if line.startswith("#separator"):
        raw = line[len("#separator") :].strip()
        header.separator = unescape_zeek(raw) or "\t"
        return
    key, _, value = line[1:].partition(header.separator)
    if key == "set_separator":
        header.set_separator = unescape_zeek(value)
    elif key == "empty_field":
        header.empty_field = value
    elif key == "unset_field":
        header.unset_field = value
    elif key == "path":
        header.path = value
    elif key == "fields":
        header.fields = value.split(header.separator)
    elif key == "types":
        header.types = value.split(header.separator)


def _iter_tsv(lines: Iterable[str], stats: ReadStats) -> Iterator[Record]:
    header = _TSVHeader()
    converters: list[Callable[[str], Any]] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        stats.lines += 1
        if line.startswith("#"):
            if line.startswith("#separator"):
                header = _TSVHeader()
            _parse_header_line(line, header)
            if line.startswith(("#fields", "#types")):
                types = header.types or [""] * len(header.fields)
                converters = [_converter(t, header) for t in types]
            continue
        if not header.fields:
            stats.malformed += 1
            continue
        values = line.split(header.separator)
        if len(values) != len(header.fields):
            # Truncated or corrupted line (e.g. a log cut off mid-write).
            stats.malformed += 1
            continue
        record: Record = {}
        try:
            for name, value, convert in zip(header.fields, values, converters, strict=True):
                record[name] = None if value == header.unset_field else convert(value)
        except (ValueError, TypeError):
            stats.malformed += 1
            continue
        yield record


def _flatten(obj: dict[str, Any], prefix: str = "") -> Record:
    out: Record = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, f"{name}."))
        else:
            out[name] = value
    return out


def _json_time(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _iter_json(lines: Iterable[str], stats: ReadStats) -> Iterator[Record]:
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        stats.lines += 1
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            stats.malformed += 1
            continue
        if not isinstance(obj, dict):
            stats.malformed += 1
            continue
        record = _flatten(obj)
        for key in _JSON_TIME_FIELDS & record.keys():
            record[key] = _json_time(record[key])
        for key in _JSON_ADDR_FIELDS & record.keys():
            if isinstance(record[key], str):
                record[key] = normalize_ip(record[key])
        yield record


def iter_file(path: str | Path, stats: ReadStats | None = None) -> Iterator[Record]:
    """Yield raw-typed records from one log file (format auto-detected)."""
    stats = stats if stats is not None else ReadStats()
    path = Path(path)
    with _open_text(path) as fh:
        first = ""
        for line in fh:
            if line.strip():
                first = line
                break
        if not first:
            return
        fmt = detect_format(first)
        stats.files += 1
        stats.formats.add(fmt)
        chained = _chain_first(first, fh)
        yield from (_iter_tsv(chained, stats) if fmt == "tsv" else _iter_json(chained, stats))


def _chain_first(first: str, rest: Iterable[str]) -> Iterator[str]:
    yield first
    yield from rest


# --- log-type specific normalization ------------------------------------------


def _normalize_dns(record: Record, drop_arpa: bool) -> bool:
    query = record.get("query")
    if isinstance(query, str):
        query = query.strip().lower().rstrip(".")
        record["query"] = query or None
        if drop_arpa and query and (query == "arpa" or query.endswith(".arpa")):
            return False
    return True


class ZeekLogReader:
    """Read and normalize all files of a log type from a directory tree."""

    def __init__(self, *, drop_arpa: bool = True) -> None:
        self.drop_arpa = drop_arpa
        self.stats: dict[str, ReadStats] = {}

    def read(
        self,
        log_dir: str | Path,
        log_type: str,
        *,
        start: float | None = None,
        end: float | None = None,
    ) -> list[Record]:
        """Return ts-sorted, de-duplicated records with ``start <= ts < end``."""
        stats = ReadStats()
        records: list[Record] = []
        for path in discover_logs(log_dir, log_type):
            for record in iter_file(path, stats):
                ts = record.get("ts")
                if not isinstance(ts, (int, float)) or isinstance(ts, bool):
                    stats.malformed += 1
                    continue
                if (start is not None and ts < start) or (end is not None and ts >= end):
                    continue
                if log_type == "dns" and not _normalize_dns(record, self.drop_arpa):
                    stats.dropped += 1
                    continue
                records.append(record)
        records = self._sort_and_dedupe(records, log_type, stats)
        stats.records = len(records)
        self.stats.setdefault(log_type, ReadStats()).merge(stats)
        return records

    @staticmethod
    def _sort_and_dedupe(records: list[Record], log_type: str, stats: ReadStats) -> list[Record]:
        records.sort(key=lambda r: (r["ts"], r.get("uid") or ""))
        out: list[Record] = []
        seen_exact: set[str] = set()
        seen_conn_uids: set[str] = set()
        for record in records:
            uid = record.get("uid")
            if log_type == "conn" and isinstance(uid, str):
                if uid in seen_conn_uids:
                    stats.duplicates += 1
                    continue
                seen_conn_uids.add(uid)
            else:
                fingerprint = json.dumps(record, sort_keys=True, default=str)
                if fingerprint in seen_exact:
                    stats.duplicates += 1
                    continue
                seen_exact.add(fingerprint)
            out.append(record)
        return out


def scan_time_bounds(log_dir: str | Path, log_types: Iterable[str]) -> tuple[float, float] | None:
    """Cheap pass computing the min/max ``ts`` across the given log types."""
    lo: float | None = None
    hi: float | None = None
    for log_type in log_types:
        for path in discover_logs(log_dir, log_type):
            for record in iter_file(path):
                ts = record.get("ts")
                if isinstance(ts, (int, float)) and not isinstance(ts, bool):
                    lo = ts if lo is None or ts < lo else lo
                    hi = ts if hi is None or ts > hi else hi
    if lo is None or hi is None:
        return None
    return float(lo), float(hi)


def total_size(log_dir: str | Path, log_types: Iterable[str]) -> int:
    return sum(p.stat().st_size for t in log_types for p in discover_logs(log_dir, t))
