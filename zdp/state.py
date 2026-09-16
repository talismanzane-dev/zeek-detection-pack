"""SQLite-backed state that persists across analysis windows and runs.

Used for baselines such as lateral-movement "first seen" admin-service pairs.
Time is *log time* (epoch seconds from Zeek records), never wall-clock time,
so replaying historical logs builds the same baseline as live processing.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import TracebackType
from typing import Any

SEED_SCHEMA_VERSION = 1
_BASELINE_STARTED = "baseline_started"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    analyzer TEXT NOT NULL,
    key      TEXT NOT NULL,
    value    TEXT NOT NULL,
    PRIMARY KEY (analyzer, key)
);
CREATE TABLE IF NOT EXISTS seen (
    analyzer   TEXT NOT NULL,
    key        TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    hits       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (analyzer, key)
);
CREATE INDEX IF NOT EXISTS seen_last ON seen (analyzer, last_seen);
"""


class StateStore:
    """A single SQLite file holding namespaced state for every analyzer."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def scoped(self, analyzer: str) -> AnalyzerState:
        return AnalyzerState(self._conn, analyzer)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.commit()
        self._conn.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- seed import/export (human-readable baselines for fixtures) ----------

    def import_seed(self, seed: Mapping[str, Any]) -> None:
        """Load a JSON-compatible seed (see ``export_seed``) into the store."""
        version = seed.get("schema_version")
        if version != SEED_SCHEMA_VERSION:
            raise ValueError(f"unsupported state seed schema_version: {version!r}")
        analyzers = seed.get("analyzers") or {}
        for name, payload in analyzers.items():
            scope = self.scoped(str(name))
            for key, value in (payload.get("meta") or {}).items():
                scope.set_meta(str(key), str(value))
            for row in payload.get("seen") or ():
                scope.observe(str(row["key"]), float(row["first_seen"]))
                scope.observe(str(row["key"]), float(row["last_seen"]))
        self.commit()

    def import_seed_file(self, path: str | Path) -> None:
        with Path(path).open(encoding="utf-8") as fh:
            self.import_seed(json.load(fh))

    def export_seed(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schema_version": SEED_SCHEMA_VERSION, "analyzers": {}}
        for analyzer, key, value in self._conn.execute(
            "SELECT analyzer, key, value FROM meta ORDER BY analyzer, key"
        ):
            out["analyzers"].setdefault(analyzer, {"meta": {}, "seen": []})["meta"][key] = value
        for analyzer, key, first, last in self._conn.execute(
            "SELECT analyzer, key, first_seen, last_seen FROM seen ORDER BY analyzer, key"
        ):
            entry = out["analyzers"].setdefault(analyzer, {"meta": {}, "seen": []})
            entry["seen"].append({"key": key, "first_seen": first, "last_seen": last})
        return out


class AnalyzerState:
    """View of the store restricted to one analyzer's namespace."""

    def __init__(self, conn: sqlite3.Connection, analyzer: str) -> None:
        self._conn = conn
        self.analyzer = analyzer

    # -- metadata -------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE analyzer = ? AND key = ?", (self.analyzer, key)
        ).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta (analyzer, key, value) VALUES (?, ?, ?) "
            "ON CONFLICT (analyzer, key) DO UPDATE SET value = excluded.value",
            (self.analyzer, key, value),
        )

    # -- baseline age ---------------------------------------------------------

    def baseline_started(self) -> float | None:
        raw = self.get_meta(_BASELINE_STARTED)
        return None if raw is None else float(raw)

    def ensure_baseline_started(self, ts: float) -> float:
        """Record the start of the baseline (earliest log time observed)."""
        started = self.baseline_started()
        if started is None or ts < started:
            self.set_meta(_BASELINE_STARTED, repr(float(ts)))
            return float(ts)
        return started

    def baseline_age(self, now: float) -> float:
        """Seconds of log time covered by the baseline as of ``now`` (0 if none)."""
        started = self.baseline_started()
        return 0.0 if started is None else max(0.0, now - started)

    # -- first-seen tracking --------------------------------------------------

    def first_seen(self, key: str) -> float | None:
        row = self._conn.execute(
            "SELECT first_seen FROM seen WHERE analyzer = ? AND key = ?", (self.analyzer, key)
        ).fetchone()
        return None if row is None else float(row[0])

    def is_known(self, key: str) -> bool:
        return self.first_seen(key) is not None

    def observe(self, key: str, ts: float) -> None:
        self._conn.execute(
            "INSERT INTO seen (analyzer, key, first_seen, last_seen, hits) VALUES (?, ?, ?, ?, 1) "
            "ON CONFLICT (analyzer, key) DO UPDATE SET "
            "first_seen = MIN(first_seen, excluded.first_seen), "
            "last_seen = MAX(last_seen, excluded.last_seen), hits = hits + 1",
            (self.analyzer, key, ts, ts),
        )

    def observe_many(self, items: Iterable[tuple[str, float]]) -> None:
        for key, ts in items:
            self.observe(key, ts)

    def expire(self, before_ts: float) -> int:
        """Drop entries not observed since ``before_ts``; returns rows removed."""
        cur = self._conn.execute(
            "DELETE FROM seen WHERE analyzer = ? AND last_seen < ?", (self.analyzer, before_ts)
        )
        return int(cur.rowcount)

    def count(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM seen WHERE analyzer = ?", (self.analyzer,)
        ).fetchone()
        return int(row[0])

    def commit(self) -> None:
        self._conn.commit()
