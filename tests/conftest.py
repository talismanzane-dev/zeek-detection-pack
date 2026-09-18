"""Shared test helpers."""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from zdp.analyzers.base import BaseAnalyzer
from zdp.config import Config
from zdp.models import LogWindow, Record
from zdp.state import StateStore

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
TEST_DATA = REPO / "tests" / "data"
T0 = 1_700_006_400.0  # 2023-11-15T00:00:00Z, hour-aligned

_uid_counter = itertools.count()


def uid() -> str:
    return f"Ctest{next(_uid_counter):013d}"


def conn(ts: float, orig: str, resp: str, port: int, **extra: Any) -> Record:
    rec: Record = {
        "ts": ts,
        "uid": uid(),
        "id.orig_h": orig,
        "id.orig_p": 50000,
        "id.resp_h": resp,
        "id.resp_p": port,
        "proto": "tcp",
        "service": None,
        "duration": 0.3,
        "orig_bytes": 900,
        "resp_bytes": 300,
        "conn_state": "SF",
    }
    rec.update(extra)
    return rec


def dns(ts: float, orig: str, query: str, qtype: str = "A", rcode: str = "NOERROR") -> Record:
    return {
        "ts": ts,
        "uid": uid(),
        "id.orig_h": orig,
        "id.resp_h": "10.1.0.53",
        "id.resp_p": 53,
        "query": query,
        "qtype_name": qtype,
        "rcode_name": rcode,
    }


def window(start: float = T0, size: float = 3600.0, **logs: list[Record]) -> LogWindow:
    return LogWindow(start=start, end=start + size, logs=logs)


@pytest.fixture(scope="session")
def config() -> Config:
    return Config.load()


@pytest.fixture
def state() -> Iterator[StateStore]:
    store = StateStore(":memory:")
    yield store
    store.close()


def configure(
    analyzer: BaseAnalyzer,
    config: Config,
    state: StateStore | None = None,
    **overrides: Any,
) -> BaseAnalyzer:
    """Configure an analyzer with optional parameter overrides."""
    from zdp.config import deep_merge

    raw = deep_merge(config.raw, {"detectors": {analyzer.name: overrides}}) if overrides else None
    cfg = config
    if raw is not None:
        cfg = Config(
            raw=raw,
            networks=config.networks,
            domains=config.domains,
            schedule=config.schedule,
            sources=config.sources,
        )
    analyzer.configure(
        cfg.analyzer_config(
            analyzer.name,
            analyzer.DEFAULTS,
            state=state.scoped(analyzer.name) if state is not None else None,
        )
    )
    return analyzer


def scenario_config(name: str) -> Config:
    site = FIXTURES / name / "site.yaml"
    return Config.load(None, [site] if site.is_file() else [])


def scenario_state(name: str) -> StateStore:
    store = StateStore(":memory:")
    seed = FIXTURES / name / "state_seed.json"
    if seed.is_file():
        store.import_seed_file(seed)
    return store
