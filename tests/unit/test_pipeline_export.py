"""Windowing, de-duplication, chunked reads, models, and rule export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from tests.conftest import FIXTURES, REPO, scenario_config, scenario_state
from zdp.config import Config
from zdp.exporters import export_rules
from zdp.models import MAX_UIDS, Detection
from zdp.pipeline import Pipeline, dedupe, window_starts
from zdp.registry import RegistryError, applicable, create_analyzers
from zdp.rules import rule_uuid, suricata_sid


class TestWindows:
    def test_tumbling_windows_are_epoch_aligned(self) -> None:
        starts = window_starts(1_700_000_000.0, 1_700_007_000.0, 3600, 0.0)
        assert starts == [1_699_999_200.0, 1_700_002_800.0, 1_700_006_400.0]

    def test_overlapping_windows_cover_every_point_twice(self) -> None:
        t_min, t_max = 1_700_000_000.0, 1_700_010_000.0
        starts = window_starts(t_min, t_max, 3600, 0.5)
        for t in (t_min, t_min + 1234.5, t_max):
            assert sum(1 for s in starts if s <= t < s + 3600) == 2

    def test_invalid_overlap(self) -> None:
        with pytest.raises(ValueError):
            window_starts(0, 10, 3600, 1.0)

    def test_dedupe_keeps_highest_confidence_per_key(self) -> None:
        def d(conf: float, ts: float) -> Detection:
            return Detection.build(
                ts=ts,
                last_ts=ts + 60,
                detector="c2_beaconing",
                src="10.0.0.1",
                dst="203.0.113.1",
                indicator="203.0.113.1:443",
                confidence=conf,
                technique_id="T1071",
                tactic="Command and Control",
                evidence={},
                uids=[],
            )

        out = dedupe([d(0.7, 100.2), d(0.9, 100.7), d(0.8, 200.0)])
        assert [(x.ts, x.confidence) for x in out] == [(100.7, 0.9), (200.0, 0.8)]


class TestPipeline:
    def test_chunked_processing_matches_full_read(self) -> None:
        name = "lateral_movement"
        cfg = scenario_config(name)
        with scenario_state(name) as s1, scenario_state(name) as s2:
            full = Pipeline(cfg, state=s1).run(FIXTURES / name)
            chunked = Pipeline(cfg, state=s2).run(FIXTURES / name, chunk_seconds=7200)
        assert chunked.chunks > 1
        assert [d.to_dict() for d in chunked.detections] == [d.to_dict() for d in full.detections]

    def test_analyzers_skipped_when_logs_missing(self, tmp_path: Path, config: Config) -> None:
        (tmp_path / "dns.log").write_text((FIXTURES / "dga" / "dns.log").read_text())
        result = Pipeline(config).run(tmp_path)
        assert set(result.analyzers_run) == {"dga", "dns_tunneling"}
        assert set(result.analyzers_skipped) == {"c2_beaconing", "lateral_movement"}

    def test_overlap_dedup_on_beacon_fixture(self) -> None:
        cfg = scenario_config("c2_beaconing")
        result = Pipeline(cfg).run(FIXTURES / "c2_beaconing")
        keys = [(d.detector, d.src, d.dst, d.indicator, int(d.ts)) for d in result.detections]
        assert len(keys) == len(set(keys))

    def test_registry(self) -> None:
        with pytest.raises(RegistryError):
            create_analyzers(["nope"])
        analyzers = create_analyzers()
        assert {a.name for a in applicable(analyzers, {"conn"})} == {
            "c2_beaconing",
            "lateral_movement",
        }


class TestDetectionModel:
    def test_build_caps_uids_and_derives_severity(self) -> None:
        det = Detection.build(
            ts=1.0,
            last_ts=2.0,
            detector="x",
            src="10.0.0.1",
            dst=None,
            indicator="i",
            confidence=0.86123456,
            technique_id="T1",
            tactic="t",
            evidence={"b": {2, 1}, "a": float("nan")},
            uids=[f"C{i}" for i in range(80)] + [None, "C1"],
        )
        assert len(det.uids) == MAX_UIDS
        assert det.severity == "high"
        assert det.confidence == 0.8612
        assert det.evidence == {"a": None, "b": [1, 2]}
        assert list(json.loads(det.to_json())) == [
            "ts",
            "last_ts",
            "detector",
            "src",
            "dst",
            "indicator",
            "confidence",
            "severity",
            "technique_id",
            "tactic",
            "evidence",
            "uids",
        ]

    def test_validation(self) -> None:
        with pytest.raises(ValueError):
            Detection(
                ts=2.0,
                last_ts=1.0,
                detector="x",
                src="s",
                dst=None,
                indicator="i",
                confidence=0.5,
                severity="low",
                technique_id="T",
                tactic="t",
                evidence={},
                uids=[],
            )


class TestExport:
    def test_export_is_deterministic_and_matches_committed_rules(
        self, tmp_path: Path, config: Config
    ) -> None:
        a, b = tmp_path / "a", tmp_path / "b"
        export_rules(config, ["sigma", "suricata"], a)
        export_rules(config, ["sigma", "suricata"], b)
        files_a = sorted(p.relative_to(a) for p in a.rglob("*") if p.is_file())
        assert files_a == sorted(p.relative_to(b) for p in b.rglob("*") if p.is_file())
        for rel in files_a:
            assert (a / rel).read_bytes() == (b / rel).read_bytes()
            committed = REPO / "rules" / rel
            assert committed.read_bytes() == (a / rel).read_bytes(), f"rules/{rel} is stale"

    def test_every_rule_declares_a_tier(self, tmp_path: Path, config: Config) -> None:
        manifest = export_rules(config, ["sigma", "suricata"], tmp_path)
        assert manifest["rules"] and all(
            r["tier"] in {"full", "approx", "companion"} for r in manifest["rules"]
        )
        for path in (tmp_path / "sigma").glob("*.yml"):
            text = path.read_text()
            assert "# zdp-tier:" in text
            for doc in yaml.safe_load_all(text):
                assert doc["title"].endswith(("[full]", "[approx]", "[companion]"))
        for path in (tmp_path / "suricata").glob("*.rules"):
            rules = [ln for ln in path.read_text().splitlines() if ln.startswith("alert")]
            assert rules and all("zdp_tier " in r for r in rules)
        skipped = {(s["detector"], s["format"]) for s in manifest["skipped"]}
        assert ("c2_beaconing", "sigma") in skipped

    def test_rule_ids_change_only_with_config(self, tmp_path: Path) -> None:
        overlay = tmp_path / "o.yaml"
        overlay.write_text(yaml.safe_dump({"detectors": {"dga": {"nx_burst_min": 11}}}))
        base = {r["id"] for r in export_rules(Config.load(), ["sigma"], tmp_path / "x")["rules"]}
        changed = export_rules(Config.load(None, [overlay]), ["sigma"], tmp_path / "y")["rules"]
        dga_ids = {r["id"] for r in changed if r["detector"] == "dga"}
        other_ids = {r["id"] for r in changed if r["detector"] != "dga"}
        assert dga_ids.isdisjoint(base)
        assert other_ids <= base
        assert rule_uuid("d", "s", "h") == rule_uuid("d", "s", "h")
        assert 1_000_000 <= suricata_sid("d", "s", "h") < 2_000_000
