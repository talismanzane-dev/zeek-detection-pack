"""The harness computes precision/recall/F1 correctly on a tiny known fixture."""

from __future__ import annotations

import json
from pathlib import Path

from tests.conftest import TEST_DATA
from zdp.harness.runner import run_harness

TINY = TEST_DATA


def test_tiny_fixture_counts_and_metrics(tmp_path: Path) -> None:
    out = tmp_path / "metrics.json"
    metrics = run_harness(TINY, out=out, reports=tmp_path / "reports")

    m = metrics["detectors"]["dns_tunneling"]
    # harness_tiny: one labeled tunnel (TP), one unlabeled tunnel (FP), one
    # label with no traffic (FN) — see tests/data/harness_tiny/README.md.
    assert (m["tp"], m["fp"], m["fn"], m["duplicates"]) == (1, 1, 1, 0)
    tp, fp, fn = m["tp"], m["fp"], m["fn"]
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    assert m["precision"] == precision
    assert m["recall"] == recall
    assert m["f1"] == 2 * precision * recall / (precision + recall)
    assert m["undefined"] == []

    # Detectors with neither labels nor detections are flagged, not silently perfect.
    for name in ("c2_beaconing", "dga", "lateral_movement"):
        empty = metrics["detectors"][name]
        assert (empty["tp"], empty["fp"], empty["fn"]) == (0, 0, 0)
        assert set(empty["undefined"]) == {"precision", "recall", "f1"}
        assert empty["precision"] == empty["recall"] == empty["f1"] == 0.0

    # Overall is the micro-average (pooled counts).
    overall = metrics["overall"]
    assert (overall["tp"], overall["fp"], overall["fn"]) == (1, 1, 1)

    # Output is reproducible and traceable.
    written = json.loads(out.read_text())
    assert written["detectors"] == metrics["detectors"]
    assert written["framework_version"]
    assert len(written["config_hash"]) == 12
    scenario = written["scenarios"]["harness_tiny"]
    assert [fn["src"] for fn in scenario["false_negatives"]] == ["10.9.0.12"]
    assert [fp["src"] for fp in scenario["false_positives"]] == ["10.9.0.11"]

    # Per-detector markdown reports are emitted.
    report = (tmp_path / "reports" / "dns_tunneling.md").read_text()
    assert "10.9.0.11" in report and "10.9.0.12" in report
    assert (tmp_path / "reports" / "summary.md").is_file()


def test_harness_script_cli(tmp_path: Path) -> None:
    import subprocess
    import sys

    from tests.conftest import REPO

    out = tmp_path / "m.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "harness.py"),
            "--fixtures",
            str(TINY),
            "--out",
            str(out),
            "--reports",
            str(tmp_path / "r"),
            "--detectors",
            "dns_tunneling",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
    )
    assert proc.returncode == 0, proc.stderr
    metrics = json.loads(out.read_text())
    assert list(metrics["detectors"]) == ["dns_tunneling"]
    assert (tmp_path / "r" / "dns_tunneling.md").is_file()
