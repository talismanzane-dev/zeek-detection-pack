"""Repository tooling: gate checks, README metrics rendering, metric-literal lint."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.conftest import REPO


def load_tool(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


check_gates = load_tool("check_gates")
render_metrics = load_tool("render_metrics")
lint = load_tool("check_no_hardcoded_metrics")


def fake_metrics(suite: str = "ctu13", **detector: Any) -> dict[str, Any]:
    det = {
        "tp": 8,
        "fp": 2,
        "fn": 2,
        "duplicates": 0,
        "precision": 0.8,
        "recall": 0.8,
        "f1": 0.8,
        "undefined": [],
    }
    det.update(detector)
    return {
        "suite": suite,
        "framework_version": "0.1.0",
        "config_hash": "abc",
        "generated_at": "now",
        "settings": {"tolerance_seconds": 120, "dedup_policy": "ignore"},
        "detectors": {"dga": det},
        "overall": det,
        "scenarios": {
            "s": {
                "n_detections": 1,
                "n_labels": 1,
                "false_negatives": [],
                "false_positives": [{"detector": "dga", "src": "x", "indicator": "y"}],
            }
        },
    }


class TestGates:
    def test_null_floors_are_pending(self) -> None:
        passed, pending, failed = check_gates.check(
            fake_metrics(), {"detectors": {"dga": {"min_precision": None, "min_recall": None}}}
        )
        assert (len(passed), len(pending), failed) == (0, 2, [])

    def test_floor_violation_and_scenario_rules(self) -> None:
        gates = {
            "detectors": {"dga": {"min_precision": 0.9, "min_recall": 0.5}},
            "scenarios": {
                "s": {"max_detections": 0, "max_false_positives": 0, "all_labels_matched": True}
            },
        }
        passed, _, failed = check_gates.check(fake_metrics(), gates)
        assert any("precision" in f for f in failed)
        assert any("detections" in f for f in failed)
        assert any("false positive" in f for f in failed)
        assert any("recall meets floor" in p for p in passed)

    def test_repo_gates_file_is_valid(self, tmp_path: Path) -> None:
        metrics = tmp_path / "m.json"
        metrics.write_text(json.dumps(fake_metrics()))
        # Scenario names won't exist in the fake metrics → failures, but parsing works.
        assert check_gates.main([str(metrics), str(REPO / "quality_gates.yaml")]) == 1


class TestRenderMetrics:
    README = f"intro\n{render_metrics.BEGIN}\nold\n{render_metrics.END}\noutro\n"

    def test_placeholder_when_no_benchmark(self, tmp_path: Path) -> None:
        block = render_metrics.render(tmp_path / "missing.json")
        assert "PLACEHOLDER: compute from CTU-13 run" in block
        assert lint.scan_text(block) == []

    def test_fixture_suite_is_never_rendered_as_benchmark(self, tmp_path: Path) -> None:
        path = tmp_path / "m.json"
        path.write_text(json.dumps(fake_metrics(suite="fixtures")))
        assert "PLACEHOLDER" in render_metrics.render(path)

    def test_benchmark_rendering_and_check(self, tmp_path: Path) -> None:
        path, readme = tmp_path / "m.json", tmp_path / "README.md"
        path.write_text(json.dumps(fake_metrics()))
        readme.write_text(self.README)
        assert (
            render_metrics.main(["--metrics", str(path), "--readme", str(readme), "--check"]) == 1
        )
        assert render_metrics.main(["--metrics", str(path), "--readme", str(readme)]) == 0
        text = readme.read_text()
        assert "| `dga` | 8 | 2 | 2 |" in text and text.endswith("outro\n")
        assert (
            render_metrics.main(["--metrics", str(path), "--readme", str(readme), "--check"]) == 0
        )
        # Values inside the generated block are allowed by the lint.
        assert lint.scan_text(text) == []


class TestMetricLint:
    @pytest.mark.parametrize(
        "text",
        [
            "Our precision is 0.93 on CTU-13.",
            "Recall: 95%",
            "achieves 0.91 F1",
            "| Detector | Precision |\n|---|---|\n| dga | 0.88 |",
            "false positive rate of 0.2%",
        ],
    )
    def test_flags_literals(self, text: str) -> None:
        assert lint.scan_text(text)

    @pytest.mark.parametrize(
        "text",
        [
            "Precision: PLACEHOLDER: compute from CTU-13 run",
            "confidence >= 0.85 maps to high severity",
            "F1 = 2PR/(P+R)",
            "| Detector | Precision |\n|---|---|\n| dga | TODO: measured value |",
            "Score 0 at <= 3.0 bits/char, 1.0 at >= 4.0",
        ],
    )
    def test_allows_non_metrics(self, text: str) -> None:
        assert lint.scan_text(text) == []

    def test_repository_docs_are_clean(self) -> None:
        assert lint.main([]) == 0


class TestCTU13Labels:
    def test_cc_flows_become_candidate_labels(self, tmp_path: Path) -> None:
        tool = load_tool("ctu13_labels")
        header = (
            "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,"
            "TotBytes,SrcBytes,Label\n"
        )
        rows = [
            f"2011/08/10 10:{m:02d}:00.000000,0.5,tcp,147.32.84.165,{1025 + m},   ->,"
            f"66.235.1.10,80,FSPA_FSPA,0,0,8,900,400,flow=From-Botnet-V42-TCP-CC6-Plain-HTTP"
            for m in range(10)
        ]
        rows += [  # botnet but not C2, and C2 below min_flows
            "2011/08/10 10:00:00.000000,0.5,tcp,147.32.84.165,2000,   ->,1.2.3.4,25,S_,0,0,1,60,60,"
            "flow=From-Botnet-V42-TCP-Attempt-SPAM",
            "2011/08/10 10:00:00.000000,0.5,udp,147.32.84.191,2001,  <->,5.6.7.8,53,CON,0,0,2,"
            "90,45,"
            "flow=From-Botnet-V42-UDP-CC1-DNS",
        ]
        src = tmp_path / "capture.binetflow"
        src.write_text(header + "\n".join(rows) + "\n")
        out = tmp_path / "ctu"
        assert (
            tool.main(["--binetflow", str(src), "--scenario", "ctu13-42", "--out-dir", str(out)])
            == 0
        )
        data = json.loads((out / "labels.json").read_text())
        (lbl,) = data["labels"]
        assert (lbl["src"], lbl["dst"], lbl["indicator"]) == (
            "147.32.84.165",
            "66.235.1.10",
            "66.235.1.10:80",
        )
        # 10:00 CEST (UTC+2) on 2011-08-10.
        assert lbl["window"][0] == 1_312_963_200.0
        assert "candidate label" in lbl["note"]
        assert "147.32.0.0/16" in (out / "site.yaml").read_text()
        from zdp.harness.labels import load_labels

        assert load_labels(out / "labels.json").labels[0].detector == "c2_beaconing"
