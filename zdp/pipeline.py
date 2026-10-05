"""Windowed batch runner: read → window → analyze → de-duplicate.

Each analyzer sees tumbling windows of its own size, processed in time order
so cross-window state (baselines) evolves exactly as it would live. Windows
may overlap (``window_overlap: 0.5`` for beaconing, spec §7.5); duplicate
emissions from overlapping windows are removed by keying on
``(detector, src, dst, indicator, ⌊first ts⌋)``.

Large inputs are processed in time-bounded chunks: each chunk re-reads only
the records it needs (``[chunk_start, chunk_end + max_window)``) and
analyzes the windows *starting* inside it, so output is identical to a
single full read while memory stays bounded by the chunk size.
"""

from __future__ import annotations

import bisect
import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from zdp.analyzers.base import BaseAnalyzer
from zdp.config import Config
from zdp.models import Detection, LogWindow, Record
from zdp.reader import ZeekLogReader, discover_logs, scan_time_bounds, total_size
from zdp.registry import applicable, create_analyzers
from zdp.state import StateStore

LOG = logging.getLogger(__name__)

#: Default size above which inputs are processed in chunks (bytes on disk).
DEFAULT_CHUNK_THRESHOLD = 512 * 1024 * 1024
DEFAULT_CHUNK_SECONDS = 86_400


@dataclass
class RunResult:
    detections: list[Detection]
    analyzers_run: list[str]
    analyzers_skipped: dict[str, str]
    read_stats: dict[str, dict[str, Any]]
    analyzer_status: dict[str, dict[str, Any]]
    time_bounds: tuple[float, float] | None
    chunks: int
    config_hash: str
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "detections": len(self.detections),
            "analyzers_run": self.analyzers_run,
            "analyzers_skipped": self.analyzers_skipped,
            "read_stats": self.read_stats,
            "analyzer_status": self.analyzer_status,
            "time_bounds": list(self.time_bounds) if self.time_bounds else None,
            "chunks": self.chunks,
            "config_hash": self.config_hash,
            "warnings": self.warnings,
        }


def window_starts(t_min: float, t_max: float, size: float, overlap: float) -> list[float]:
    """Start times of windows covering ``[t_min, t_max]``.

    Windows are aligned to multiples of the step (``size · (1 − overlap)``)
    from the epoch, so the same data always lands in the same windows
    regardless of where a run begins.
    """
    if size <= 0:
        raise ValueError("window size must be positive")
    if not 0.0 <= overlap < 1.0:
        raise ValueError("window_overlap must be in [0, 1)")
    step = size * (1.0 - overlap)
    first = math.floor(t_min / step) * step
    # Include earlier windows that still cover t_min when windows overlap.
    while first - step + size > t_min:
        first -= step
    starts: list[float] = []
    start = first
    while start <= t_max:
        if start + size > t_min:
            starts.append(start)
        start += step
    return starts


def dedupe(detections: Sequence[Detection]) -> list[Detection]:
    best: dict[tuple[str, str, str | None, str, int], Detection] = {}
    for det in detections:
        key = (det.detector, det.src, det.dst, det.indicator, math.floor(det.ts))
        current = best.get(key)
        if current is None or det.confidence > current.confidence:
            best[key] = det
    return sorted(best.values(), key=Detection.sort_key)


class Pipeline:
    def __init__(
        self,
        config: Config,
        analyzers: Sequence[BaseAnalyzer] | None = None,
        state: StateStore | None = None,
    ) -> None:
        self.config = config
        if analyzers is None:
            names = [name for name in _registry_names() if config.detector_enabled(name)]
            analyzers = create_analyzers(names)
        self.analyzers = list(analyzers)
        self._owns_state = state is None
        self.state = state if state is not None else StateStore(":memory:")
        for analyzer in self.analyzers:
            analyzer.configure(
                config.analyzer_config(
                    analyzer.name, analyzer.DEFAULTS, state=self.state.scoped(analyzer.name)
                )
            )

    def run(self, log_dir: str | Path, *, chunk_seconds: float | None = None) -> RunResult:
        log_dir = Path(log_dir)
        if not log_dir.exists():
            raise FileNotFoundError(f"log directory not found: {log_dir}")
        candidate_logs = {t for a in self.analyzers for t in a.required_logs | a.optional_logs}
        present = {t for t in candidate_logs if discover_logs(log_dir, t)}
        runnable = applicable(self.analyzers, present)
        skipped = {
            a.name: f"missing required logs: {sorted(a.required_logs - present)}"
            for a in self.analyzers
            if a not in runnable
        }
        needed = sorted(
            {t for a in runnable for t in (a.required_logs | a.optional_logs)} & present
        )

        reader = ZeekLogReader(drop_arpa=self.config.drop_arpa)
        bounds = scan_time_bounds(log_dir, needed) if needed else None
        detections: list[Detection] = []
        chunks = 0
        if bounds is not None and runnable:
            chunk = self._chunk_seconds(log_dir, needed, chunk_seconds)
            max_window = max(a.config.window_seconds for a in runnable)
            plans = {
                a.name: window_starts(
                    bounds[0], bounds[1], a.config.window_seconds, a.config.window_overlap
                )
                for a in runnable
            }
            earliest = min(starts[0] for starts in plans.values())
            chunk_start = earliest
            while chunk_start <= bounds[1]:
                chunk_end = chunk_start + chunk if chunk else math.inf
                logs = {
                    t: reader.read(
                        log_dir,
                        t,
                        start=chunk_start,
                        end=None if math.isinf(chunk_end) else chunk_end + max_window,
                    )
                    for t in needed
                }
                ts_index = {t: [r["ts"] for r in recs] for t, recs in logs.items()}
                for analyzer in runnable:
                    for start in plans[analyzer.name]:
                        if not chunk_start <= start < chunk_end:
                            continue
                        window = _slice(
                            logs, ts_index, start, start + analyzer.config.window_seconds
                        )
                        detections.extend(analyzer.analyze(window))
                self.state.commit()
                chunks += 1
                if math.isinf(chunk_end):
                    break
                chunk_start = chunk_end

        return RunResult(
            detections=dedupe(detections),
            analyzers_run=[a.name for a in runnable],
            analyzers_skipped=skipped,
            read_stats={t: s.as_dict() for t, s in sorted(reader.stats.items())},
            analyzer_status={a.name: a.status() for a in runnable},
            time_bounds=bounds,
            chunks=chunks,
            config_hash=self.config.config_hash(),
        )

    def close(self) -> None:
        if self._owns_state:
            self.state.close()

    def _chunk_seconds(
        self, log_dir: Path, log_types: Sequence[str], override: float | None
    ) -> float | None:
        if override is not None:
            return override if override > 0 else None
        settings = self.config.runner
        threshold = int(settings.get("chunk_threshold_bytes", DEFAULT_CHUNK_THRESHOLD))
        if total_size(log_dir, log_types) <= threshold:
            return None
        return float(settings.get("chunk_seconds", DEFAULT_CHUNK_SECONDS))


def _slice(
    logs: dict[str, list[Record]], ts_index: dict[str, list[float]], start: float, end: float
) -> LogWindow:
    sliced: dict[str, list[Record]] = {}
    for log_type, records in logs.items():
        idx = ts_index[log_type]
        lo = bisect.bisect_left(idx, start)
        hi = bisect.bisect_left(idx, end)
        sliced[log_type] = records[lo:hi]
    return LogWindow(start=start, end=end, logs=sliced)


def _registry_names() -> list[str]:
    from zdp.registry import available_analyzers

    return list(available_analyzers())
