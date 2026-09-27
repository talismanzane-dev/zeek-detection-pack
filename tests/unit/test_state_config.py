"""StateStore warm-up behaviour, configuration loading, PSL and bigram data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from zdp.config import Config, ConfigError, deep_merge
from zdp.lexical import calibrate_random_baseline, get_model
from zdp.psl import get_parser
from zdp.registry import available_analyzers
from zdp.state import StateStore

DAY = 86_400.0


class TestStateStore:
    def test_baseline_age_and_warmup(self, state: StateStore) -> None:
        scope = state.scoped("lateral_movement")
        assert scope.baseline_started() is None
        assert scope.baseline_age(1_000.0) == 0.0
        scope.ensure_baseline_started(1_000.0)
        scope.ensure_baseline_started(5_000.0)  # later ts never moves the start forward
        assert scope.baseline_started() == 1_000.0
        assert scope.baseline_age(1_000.0 + 6 * DAY) < 7 * DAY
        assert scope.baseline_age(1_000.0 + 7 * DAY) == 7 * DAY

    def test_observe_first_seen_and_expiry(self, state: StateStore) -> None:
        scope = state.scoped("x")
        scope.observe("a|b|445", 200.0)
        scope.observe("a|b|445", 100.0)
        assert scope.first_seen("a|b|445") == 100.0
        assert scope.is_known("a|b|445")
        assert not state.scoped("other").is_known("a|b|445")  # namespaced per analyzer
        scope.observe("c|d|22", 50.0)
        assert scope.expire(150.0) == 1  # c|d|22 last seen at 50
        assert scope.count() == 1

    def test_seed_round_trip_and_persistence(self, tmp_path: Path) -> None:
        db = tmp_path / "state.db"
        with StateStore(db) as store:
            store.scoped("lm").set_meta("baseline_started", "10.0")
            store.scoped("lm").observe("k", 20.0)
            seed = store.export_seed()
        with StateStore(db) as reopened:
            assert reopened.scoped("lm").is_known("k")
        with StateStore() as fresh:
            fresh.import_seed(seed)
            assert fresh.export_seed() == seed
        with pytest.raises(ValueError):
            StateStore().import_seed({"schema_version": 99})


class TestConfig:
    def test_default_yaml_mirrors_analyzer_defaults(self, config: Config) -> None:
        for name, cls in available_analyzers().items():
            section = dict(config.raw["detectors"][name])
            section.pop("enabled")
            assert json.loads(json.dumps(section)) == json.loads(json.dumps(dict(cls.DEFAULTS))), (
                name
            )

    def test_all_weights_sum_to_one(self, config: Config) -> None:
        for name, cls in available_analyzers().items():
            analyzer = cls()
            analyzer.configure(config.analyzer_config(name, cls.DEFAULTS))  # validates weights

    def test_unknown_parameter_rejected(self, tmp_path: Path) -> None:
        overlay = tmp_path / "o.yaml"
        overlay.write_text(yaml.safe_dump({"detectors": {"dga": {"nx_burst_minimum": 3}}}))
        cfg = Config.load(None, [overlay])
        with pytest.raises(ConfigError, match="unknown parameters"):
            cfg.detector_params("dga", available_analyzers()["dga"].DEFAULTS)

    def test_site_overlay_extends_policy(self, tmp_path: Path) -> None:
        overlay = tmp_path / "site.yaml"
        overlay.write_text(
            yaml.safe_dump(
                {
                    "detectors": {"dga": {"nx_burst_min": 15}},
                    "site": {
                        "networks": {"scanner_hosts": ["10.9.9.9/32"]},
                        "allow_domains": ["corp-saas.example"],
                        "internal_zones": ["corp.example.org"],
                    },
                }
            )
        )
        base = Config.load()
        cfg = Config.load(None, [overlay])
        assert cfg.networks.is_scanner_host("10.9.9.9")
        assert cfg.networks.allowlist_category("216.239.35.0") == "ntp"  # base list kept
        assert cfg.domains.is_allowlisted("corp-saas.example")
        assert cfg.domains.in_internal_zone("wpad.corp.example.org")
        assert (
            cfg.detector_params("dga", available_analyzers()["dga"].DEFAULTS)["nx_burst_min"] == 15
        )
        assert cfg.config_hash() != base.config_hash()

    def test_lateral_allow_source_requires_justification(self, tmp_path: Path) -> None:
        overlay = tmp_path / "site.yaml"
        overlay.write_text(
            yaml.safe_dump(
                {"site": {"networks": {"lateral_allow_sources": [{"cidr": "10.0.0.1/32"}]}}}
            )
        )
        with pytest.raises(ConfigError, match="justification"):
            Config.load(None, [overlay])

    def test_deep_merge_replaces_lists(self) -> None:
        assert deep_merge({"a": {"b": [1, 2], "c": 1}}, {"a": {"b": [3]}}) == {
            "a": {"b": [3], "c": 1}
        }

    def test_policy_defaults(self, config: Config) -> None:
        assert config.networks.is_internal("10.20.30.40")
        assert config.networks.is_internal("fd00::5")
        assert not config.networks.is_internal("203.0.113.5")
        assert config.domains.is_allowlisted("google.com")
        # Exact registered-domain matching: a parent entry does not cover a
        # separately registrable name under a private suffix.
        assert not config.domains.is_allowlisted("attacker.duckdns.org", "x.attacker.duckdns.org")


class TestPSL:
    @pytest.mark.parametrize(
        ("name", "registered"),
        [
            ("www.example.co.uk", "example.co.uk"),
            ("a.b.c.google.com", "google.com"),
            ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),  # private suffix honoured
            ("d111.cloudfront.net", "d111.cloudfront.net"),
            ("WWW.EXAMPLE.NET.", "example.net"),
            ("localhost", None),  # single label: no public suffix
            ("192.0.2.1", None),
        ],
    )
    def test_registered_domain(self, name: str, registered: str | None) -> None:
        assert get_parser().registered_domain(name) == registered

    def test_pinned_snapshot_has_version(self) -> None:
        assert get_parser().version() != "unknown"


class TestBigramTable:
    def test_calibration_is_derived_from_bundled_table(self) -> None:
        model = get_model()
        # The shipped one_at anchor must be reproducible from the table itself.
        assert calibrate_random_baseline(model) == pytest.approx(model.one_at, abs=1e-4)
        assert model.zero_at > model.one_at
        assert model.provenance["tranco_list_id"]

    def test_random_labels_score_lower_than_dictionary_words(self) -> None:
        model = get_model()
        words = ["microsoft", "weather", "shopping", "university", "football"]
        randoms = ["xqzvkjwprt", "qjxkzvbnmw", "zxkqpwvjht", "kq3zx9vjwp", "vbqxzkjwmr"]
        assert max(model.mean_logprob(w) for w in randoms) < min(
            model.mean_logprob(w) for w in words
        )
