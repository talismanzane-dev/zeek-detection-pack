#!/usr/bin/env python3
"""Compare a runtime ``metrics.json`` with ``quality_gates.yaml``.

Exit status: 0 when every enforced gate passes (floors that are still
``null`` are reported as PENDING and do not fail the build), 1 on any
violation, 2 on malformed input.

    python tools/check_gates.py metrics.json quality_gates.yaml
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import yaml


def check(metrics: dict[str, Any], gates: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Return (passed, pending, failed) human-readable lines."""
    passed: list[str] = []
    pending: list[str] = []
    failed: list[str] = []

    for name, floors in (gates.get("detectors") or {}).items():
        m = metrics.get("detectors", {}).get(name)
        if m is None:
            failed.append(f"detector {name}: missing from metrics.json")
            continue
        for metric in ("precision", "recall"):
            floor = (floors or {}).get(f"min_{metric}")
            if floor is None:
                pending.append(
                    f"detector {name}: min_{metric} not set (awaiting reviewed baseline)"
                )
                continue
            if metric in m.get("undefined", []):
                failed.append(f"detector {name}: {metric} undefined (zero denominator), floor set")
            elif m[metric] < float(floor):
                failed.append(
                    f"detector {name}: {metric} {m[metric]:.4f} < floor {float(floor):.4f}"
                )
            else:
                passed.append(f"detector {name}: {metric} meets floor")

    scenarios = metrics.get("scenarios", {})
    for name, rules in (gates.get("scenarios") or {}).items():
        s = scenarios.get(name)
        if s is None:
            failed.append(f"scenario {name}: not present in metrics.json")
            continue
        spec = rules or {}
        if "max_detections" in spec:
            limit = int(spec["max_detections"])
            if s["n_detections"] > limit:
                failed.append(f"scenario {name}: {s['n_detections']} detections > {limit}")
            else:
                passed.append(f"scenario {name}: detections <= {limit}")
        if spec.get("all_labels_matched"):
            missed = s["false_negatives"]
            if missed:
                notes = "; ".join(f"{m['detector']} {m['src']}" for m in missed)
                failed.append(f"scenario {name}: {len(missed)} label(s) unmatched ({notes})")
            else:
                passed.append(f"scenario {name}: all {s['n_labels']} label(s) matched")
        if "max_false_positives" in spec:
            limit = int(spec["max_false_positives"])
            fps = s["false_positives"]
            if len(fps) > limit:
                notes = "; ".join(f"{f['detector']} {f['src']} {f['indicator']}" for f in fps[:5])
                failed.append(f"scenario {name}: {len(fps)} false positive(s) > {limit} ({notes})")
            else:
                passed.append(f"scenario {name}: false positives <= {limit}")
    return passed, pending, failed


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        metrics = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        gates = yaml.safe_load(Path(args[1]).read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if gates.get("schema_version") != 1:
        print("error: unsupported quality_gates schema_version", file=sys.stderr)
        return 2
    passed, pending, failed = check(metrics, gates)
    print(
        f"quality gates for suite={metrics.get('suite')} "
        f"version={metrics.get('framework_version')} config={metrics.get('config_hash')}"
    )
    for line in passed:
        print(f"  PASS     {line}")
    for line in pending:
        print(f"  PENDING  {line}")
    for line in failed:
        print(f"  FAIL     {line}")
    print(f"{len(passed)} passed, {len(pending)} pending, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
