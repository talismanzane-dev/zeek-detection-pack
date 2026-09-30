"""Command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.conftest import FIXTURES, TEST_DATA
from zdp.cli import main


def test_list_and_selftest(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    assert "lateral_movement" in capsys.readouterr().out
    assert main(["selftest"]) == 0
    assert "selftest ok" in capsys.readouterr().out


def test_run_with_overlay_seed_and_summary(tmp_path: Path) -> None:
    name = "lateral_movement"
    out, summary = tmp_path / "d.jsonl", tmp_path / "s.json"
    rc = main(
        [
            "run",
            "--logs",
            str(FIXTURES / name),
            "--detectors",
            name,
            "--out",
            str(out),
            "--overlay",
            str(FIXTURES / name / "site.yaml"),
            "--state-seed",
            str(FIXTURES / name / "state_seed.json"),
            "--summary",
            str(summary),
        ]
    )
    assert rc == 0
    detections = [json.loads(line) for line in out.read_text().splitlines()]
    assert {d["technique_id"] for d in detections} == {"T1021.002", "T1046"}
    status = json.loads(summary.read_text())["analyzer_status"][name]
    assert status["baseline_warmup"] is False


def test_run_persistent_state_and_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "state.db"
    assert main(["run", "--logs", str(FIXTURES / "dga"), "--state", str(db)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert any('"detector":"dga"' in line for line in lines)
    assert db.is_file()


def test_view_renders_table(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "d.jsonl"
    assert main(["run", "--logs", str(FIXTURES / "dns_tunneling"), "--out", str(out)]) == 0
    capsys.readouterr()
    assert main(["view", str(out)]) == 0
    assert "dns_tunneling" in capsys.readouterr().out


def test_export_and_harness_subcommands(tmp_path: Path) -> None:
    assert main(["export", "--format", "sigma", "--out", str(tmp_path / "rules")]) == 0
    assert list((tmp_path / "rules" / "sigma").glob("*.yml"))
    metrics = tmp_path / "m.json"
    rc = main(
        ["harness", "--fixtures", str(TEST_DATA), "--out", str(metrics), "--no-reports", "-q"]
    )
    assert rc == 0 and metrics.is_file()


def test_errors_return_nonzero(tmp_path: Path) -> None:
    assert main(["run", "--logs", str(tmp_path / "missing")]) == 2
    assert main(["run", "--logs", str(tmp_path), "--config", str(tmp_path / "nope.yaml")]) == 2
