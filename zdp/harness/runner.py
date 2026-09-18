"""Labeled-fixture harness: discovery, matching, metrics, reports (spec §4).

Usage::

    python -m zdp.harness --fixtures fixtures --out metrics.json --reports reports

Each scenario directory holds Zeek logs plus ``labels.json`` and may add a
``site.yaml`` overlay (site inventory: scanner hosts, allowlisted servers)
and a ``state_seed.json`` baseline. Every scenario runs against a fresh
in-memory state store so results are reproducible and order-independent.

Metrics are computed *only* here, at runtime. They are pooled per detector
and micro-averaged overall; the output records the framework version and a
config hash so a result can be traced to the exact code and thresholds.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zdp import __version__
from zdp.config import Config, canonical_hash
from zdp.harness.labels import LabelSet, load_labels
from zdp.harness.matching import DEDUP_POLICIES, DEFAULT_TOLERANCE, Counts, MatchResult, match
from zdp.harness.report import write_reports
from zdp.models import Detection
from zdp.pipeline import Pipeline
from zdp.registry import available_analyzers, create_analyzers
from zdp.state import StateStore

LOG = logging.getLogger(__name__)
METRICS_SCHEMA_VERSION = 1
# TODO: per-detector markdown reports (see report.py).


@dataclass
class ScenarioResult:
    name: str
    path: Path
    labels: LabelSet
    detections: list[Detection]
    matches: dict[str, MatchResult]
    config_hash: str
    run_summary: dict[str, Any] = field(default_factory=dict)

    def counts(self) -> dict[str, Counts]:
        return {name: m.counts() for name, m in self.matches.items()}


def discover_scenarios(root: str | Path) -> list[Path]:
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"fixtures directory not found: {root}")
    return sorted(p for p in root.iterdir() if (p / "labels.json").is_file())


def run_scenario(
    path: Path,
    *,
    config_path: Path | None,
    detectors: Sequence[str],
    tolerance: float,
    dedup_policy: str,
) -> ScenarioResult:
    labels = load_labels(path / "labels.json")
    overlays = [path / "site.yaml"] if (path / "site.yaml").is_file() else []
    config = Config.load(config_path, overlays)
    with StateStore(":memory:") as state:
        seed = path / "state_seed.json"
        if seed.is_file():
            state.import_seed_file(seed)
        pipeline = Pipeline(config, analyzers=create_analyzers(detectors), state=state)
        result = pipeline.run(path)
    matches: dict[str, MatchResult] = {}
    for name in detectors:
        matches[name] = match(
            [d for d in result.detections if d.detector == name],
            [lbl for lbl in labels.labels if lbl.detector == name],
            tolerance=tolerance,
            dedup_policy=dedup_policy,
        )
    unknown = {lbl.detector for lbl in labels.labels} - set(detectors)
    if unknown:
        LOG.warning("%s: labels reference detectors not run: %s", path.name, sorted(unknown))
    return ScenarioResult(
        name=path.name,
        path=path,
        labels=labels,
        detections=result.detections,
        matches=matches,
        config_hash=config.config_hash(),
        run_summary=result.summary(),
    )


def _detection_brief(det: Detection) -> dict[str, Any]:
    return {
        "detector": det.detector,
        "src": det.src,
        "dst": det.dst,
        "indicator": det.indicator,
        "ts": det.ts,
        "last_ts": det.last_ts,
        "confidence": det.confidence,
        "severity": det.severity,
        "technique_id": det.technique_id,
    }


def build_metrics(
    results: Sequence[ScenarioResult],
    *,
    detectors: Sequence[str],
    base_config: Config,
    tolerance: float,
    dedup_policy: str,
    suite: str,
) -> dict[str, Any]:
    per_detector = {name: Counts() for name in detectors}
    scenarios: dict[str, Any] = {}
    for res in results:
        counts = res.counts()
        for name, c in counts.items():
            per_detector[name] = per_detector[name] + c
        scenarios[res.name] = {
            "pure_negative": res.labels.is_pure_negative,
            "n_labels": len(res.labels.labels),
            "n_detections": len(res.detections),
            "config_hash": res.config_hash,
            "detectors": {name: counts[name].metrics() for name in detectors},
            "false_positives": [
                _detection_brief(d) for m in res.matches.values() for d in m.false_positives
            ],
            "false_negatives": [
                lbl.to_dict() for m in res.matches.values() for lbl in m.false_negatives
            ],
            "duplicates": sum(len(m.duplicates) for m in res.matches.values()),
            "analyzer_status": res.run_summary.get("analyzer_status", {}),
            "read_stats": res.run_summary.get("read_stats", {}),
        }
    overall = sum(per_detector.values(), Counts())
    return {
        "schema_version": METRICS_SCHEMA_VERSION,
        "suite": suite,
        "framework_version": __version__,
        "config_hash": base_config.config_hash(),
        "config_sources": base_config.sources,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "settings": {
            "tolerance_seconds": tolerance,
            "dedup_policy": dedup_policy,
            "detectors": list(detectors),
            "settings_hash": canonical_hash(
                {"tolerance": tolerance, "dedup": dedup_policy, "detectors": list(detectors)}
            ),
        },
        "detectors": {name: per_detector[name].metrics() for name in detectors},
        "overall": overall.metrics(),
        "scenarios": scenarios,
    }


def run_harness(
    fixtures: str | Path,
    *,
    config_path: Path | None = None,
    detectors: Sequence[str] | None = None,
    tolerance: float = DEFAULT_TOLERANCE,
    dedup_policy: str = "ignore",
    suite: str = "fixtures",
    out: Path | None = None,
    reports: Path | None = None,
    detections_dir: Path | None = None,
) -> dict[str, Any]:
    base_config = Config.load(config_path)
    names = (
        list(detectors)
        if detectors
        else [n for n in available_analyzers() if base_config.detector_enabled(n)]
    )
    results = [
        run_scenario(
            path,
            config_path=config_path,
            detectors=names,
            tolerance=tolerance,
            dedup_policy=dedup_policy,
        )
        for path in discover_scenarios(fixtures)
    ]
    metrics = build_metrics(
        results,
        detectors=names,
        base_config=base_config,
        tolerance=tolerance,
        dedup_policy=dedup_policy,
        suite=suite,
    )
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    if reports is not None:
        write_reports(metrics, results, reports)
    if detections_dir is not None:
        detections_dir.mkdir(parents=True, exist_ok=True)
        for res in results:
            lines = "".join(d.to_json() + "\n" for d in res.detections)
            (detections_dir / f"{res.name}.jsonl").write_text(lines, encoding="utf-8")
    return metrics


def _print_summary(metrics: dict[str, Any]) -> None:
    print(
        f"zdp harness — suite={metrics['suite']} version={metrics['framework_version']} "
        f"config={metrics['config_hash']}"
    )
    header = (
        f"{'detector':18s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'dup':>4s}  precision  recall    F1"
    )
    print(header)
    rows = [*metrics["detectors"].items(), ("overall", metrics["overall"])]
    for name, m in rows:
        flags = f"  (undefined: {', '.join(m['undefined'])})" if m["undefined"] else ""
        print(
            f"{name:18s} {m['tp']:4d} {m['fp']:4d} {m['fn']:4d} {m['duplicates']:4d}  "
            f"{m['precision']:9.3f} {m['recall']:7.3f} {m['f1']:5.3f}{flags}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m zdp.harness",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--fixtures", type=Path, default=Path("fixtures"))
    ap.add_argument("--out", type=Path, default=Path("metrics.json"))
    ap.add_argument(
        "--reports", default="reports", help="directory for per-detector markdown reports"
    )
    ap.add_argument("--no-reports", action="store_true", help="skip markdown reports")
    ap.add_argument("--detections-dir", type=Path, help="also write per-scenario detections")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--detectors", help="comma-separated subset")
    ap.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    ap.add_argument("--dedup-policy", choices=DEDUP_POLICIES, default="ignore")
    ap.add_argument(
        "--suite",
        default="fixtures",
        help="name recorded in metrics.json (e.g. 'fixtures', 'ctu13')",
    )
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    detectors = [d.strip() for d in args.detectors.split(",")] if args.detectors else None
    metrics = run_harness(
        args.fixtures,
        config_path=args.config,
        detectors=detectors,
        tolerance=args.tolerance,
        dedup_policy=args.dedup_policy,
        suite=args.suite,
        out=args.out,
        reports=None if args.no_reports or not args.reports else Path(args.reports),
        detections_dir=args.detections_dir,
    )
    if not args.quiet:
        _print_summary(metrics)
        print(f"metrics written to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
