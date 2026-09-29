"""End-to-end harness runs over the bundled fixtures (spec §4.5 system tests).

These are correctness assertions about synthetic fixtures with known ground
truth — not performance measurements.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.conftest import FIXTURES, REPO
from zdp.harness.runner import discover_scenarios, run_harness

pytestmark = pytest.mark.system

TP_SCENARIOS = ("c2_beaconing", "beacon_jittered", "dns_tunneling", "dga", "lateral_movement")


@pytest.fixture(scope="module")
def metrics(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    out = tmp_path_factory.mktemp("harness")
    return run_harness(FIXTURES, out=out / "metrics.json", reports=out / "reports")


def test_all_spec_scenarios_present() -> None:
    names = {p.name for p in discover_scenarios(FIXTURES)}
    assert names == {"benign_office", "fp_traps", *TP_SCENARIOS}


@pytest.mark.parametrize("name", ["benign_office", "fp_traps"])
def test_negative_scenarios_yield_zero_detections(metrics: dict[str, Any], name: str) -> None:
    scenario = metrics["scenarios"][name]
    assert scenario["pure_negative"]
    assert scenario["n_detections"] == 0, scenario["false_positives"]


@pytest.mark.parametrize("name", TP_SCENARIOS)
def test_every_injected_event_is_matched(metrics: dict[str, Any], name: str) -> None:
    scenario = metrics["scenarios"][name]
    assert scenario["n_labels"] > 0
    assert scenario["false_negatives"] == []
    assert scenario["false_positives"] == []


def test_quality_gates_pass(metrics: dict[str, Any], tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("check_gates", REPO / "tools" / "check_gates.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    gates = yaml.safe_load((REPO / "quality_gates.yaml").read_text())
    _, _, failed = module.check(metrics, gates)
    assert failed == []


def test_both_log_formats_and_ipv6_are_exercised(metrics: dict[str, Any]) -> None:
    formats = {
        fmt
        for s in metrics["scenarios"].values()
        for stats in s["read_stats"].values()
        for fmt in stats["formats"]
    }
    assert formats == {"tsv", "json"}
    labels = json.loads((FIXTURES / "c2_beaconing" / "labels.json").read_text())["labels"]
    assert any(":" in lbl["src"] for lbl in labels)


def test_lateral_baseline_is_mature_in_seeded_scenarios(metrics: dict[str, Any]) -> None:
    status = metrics["scenarios"]["lateral_movement"]["analyzer_status"]["lateral_movement"]
    assert status["baseline_warmup"] is False


def test_reports_written(metrics: dict[str, Any], tmp_path_factory: pytest.TempPathFactory) -> None:
    out = tmp_path_factory.mktemp("reports")
    run_harness(FIXTURES, detectors=["dga"], reports=out)
    assert (out / "dga.md").read_text().startswith("# Harness report: `dga`")
