"""Each detector's module-level ``analyze(log_dir)`` returns Detections on its fixture."""

from __future__ import annotations

import json

import pytest

from tests.conftest import FIXTURES, scenario_config, scenario_state
from zdp.analyzers import c2_beaconing, dga, dns_tunneling, lateral_movement
from zdp.models import Detection

MODULES = {
    "c2_beaconing": c2_beaconing,
    "dns_tunneling": dns_tunneling,
    "dga": dga,
    "lateral_movement": lateral_movement,
}


def _labels(name: str) -> list[dict[str, object]]:
    data = json.loads((FIXTURES / name / "labels.json").read_text())
    return list(data["labels"])


@pytest.mark.parametrize("name", sorted(MODULES))
def test_analyze_returns_detections_on_own_fixture(name: str) -> None:
    module = MODULES[name]
    with scenario_state(name) as state:
        detections = module.analyze(FIXTURES / name, config=scenario_config(name), state=state)
    assert detections, f"{name} produced no detections on fixtures/{name}"
    assert all(isinstance(d, Detection) for d in detections)
    assert {d.detector for d in detections} == {name}
    # Every labeled source is detected.
    labeled_sources = {str(lbl["src"]) for lbl in _labels(name)}
    assert labeled_sources <= {d.src for d in detections}


@pytest.mark.parametrize("name", sorted(MODULES))
def test_detection_fields_are_well_formed(name: str) -> None:
    module = MODULES[name]
    with scenario_state(name) as state:
        detections = module.analyze(FIXTURES / name, config=scenario_config(name), state=state)
    for det in detections:
        assert det.ts <= det.last_ts
        assert 0.0 <= det.confidence <= 1.0
        assert det.severity in {"low", "medium", "high"}
        assert det.technique_id.startswith("T")
        assert det.tactic
        assert det.indicator
        assert 0 < len(det.uids) <= 50
        assert det.evidence
        # Round-trips through the stable JSON form.
        assert Detection.from_dict(json.loads(det.to_json())) == det


def test_default_analyze_without_explicit_config() -> None:
    detections = dns_tunneling.analyze(FIXTURES / "dns_tunneling")
    assert any(d.indicator == "example.net" for d in detections)


def test_technique_ids_match_attack_mapping() -> None:
    with scenario_state("lateral_movement") as state:
        lateral = lateral_movement.analyze(
            FIXTURES / "lateral_movement",
            config=scenario_config("lateral_movement"),
            state=state,
        )
    assert {d.technique_id for d in lateral} == {"T1021.002", "T1046"}
    scan = next(d for d in lateral if d.technique_id == "T1046")
    assert scan.tactic == "Discovery"
    assert scan.evidence["pattern"] == "scan"
    assert {d.technique_id for d in dga.analyze(FIXTURES / "dga")} == {"T1568.002"}
    beacons = c2_beaconing.analyze(
        FIXTURES / "c2_beaconing", config=scenario_config("c2_beaconing")
    )
    assert {d.technique_id for d in beacons} == {"T1071.001"}
