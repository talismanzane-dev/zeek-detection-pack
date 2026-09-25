"""DGA analyzer (spec §2.3, §7.3)."""

from __future__ import annotations

import random
import string
from pathlib import Path

import pytest
import yaml

from tests.conftest import T0, configure, dns, window
from zdp.analyzers.dga import DGAAnalyzer
from zdp.config import Config
from zdp.lexical import get_model

HOST = "10.1.4.31"


def random_domains(n: int, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    letters = string.ascii_lowercase
    return [
        "".join(rng.choice(letters) for _ in range(rng.randrange(10, 17)))
        + rng.choice([".com", ".net"])
        for _ in range(n)
    ]


def nx(domains: list[str], spacing: float = 6.0, host: str = HOST) -> list[dict[str, object]]:
    return [dns(T0 + 60 + spacing * i, host, d, rcode="NXDOMAIN") for i, d in enumerate(domains)]


@pytest.fixture
def analyzer(config: Config) -> DGAAnalyzer:
    return configure(DGAAnalyzer(), config)  # type: ignore[return-value]


def test_burst_of_random_names_detected(analyzer: DGAAnalyzer) -> None:
    (det,) = analyzer.analyze(window(dns=nx(random_domains(40))))
    assert det.src == det.indicator == HOST
    assert det.dst is None
    assert det.technique_id == "T1568.002"
    ev = det.evidence
    assert ev["n_nxdomain_unique"] == 40
    assert ev["c_burst"] == pytest.approx((40 - 10) / 40)
    assert ev["c_lexical"] >= 0.4
    assert len(ev["candidates"]) == 20
    assert ev["burst_end"] - ev["burst_start"] <= 300
    # Bigram anchors come from the bundled table, not from code.
    model = get_model()
    assert ev["bigram_anchors"] == {"zero_at": model.zero_at, "one_at": model.one_at}


def test_same_dead_domain_does_not_burst(analyzer: DGAAnalyzer) -> None:
    assert analyzer.analyze(window(dns=nx(["telemetry.dead-vendor.example.org"] * 200, 1.0))) == []


def test_burst_alone_is_insufficient(analyzer: DGAAnalyzer) -> None:
    words = [
        "weatherforecast",
        "shoppingcenter",
        "universitynews",
        "footballscores",
        "gardeningtips",
        "cookingrecipes",
        "travelguides",
        "musicfestival",
    ]
    domains = [f"{w}{i}.com" for i in range(5) for w in words]  # 40 names, dictionary-like
    assert analyzer.analyze(window(dns=nx(domains))) == []


def test_spread_out_nxdomains_do_not_form_a_burst(analyzer: DGAAnalyzer) -> None:
    assert analyzer.analyze(window(dns=nx(random_domains(40), spacing=85.0))) == []


def test_single_label_probes_excluded(analyzer: DGAAnalyzer) -> None:
    probes = [d.split(".")[0] for d in random_domains(40)]
    assert analyzer.analyze(window(dns=nx(probes))) == []


def test_internal_zone_excluded(tmp_path: Path) -> None:
    overlay = tmp_path / "site.yaml"
    overlay.write_text(yaml.safe_dump({"site": {"internal_zones": ["corp.example.com"]}}))
    a = configure(DGAAnalyzer(), Config.load(None, [overlay]))
    rng = random.Random(1)
    names = [
        f"{''.join(rng.choice('qxzkjv') for _ in range(12))}.corp.example.com" for _ in range(40)
    ]
    assert a.analyze(window(dns=nx(names))) == []


def test_lexical_scores_rank_random_above_words(analyzer: DGAAnalyzer) -> None:
    assert (
        analyzer.lexical_scores("xkqzvbjwtpl")["lexical"]
        > analyzer.lexical_scores("weather")["lexical"]
    )


def test_sigma_export(config: Config) -> None:
    a = configure(DGAAnalyzer(), config, nx_burst_min=12)
    (rule,) = a.to_sigma()
    corr = rule.document["correlation"]
    assert corr["type"] == "value_count"
    assert corr["condition"] == {"gte": 12, "field": "query"}
    assert corr["timespan"] == "5m"
    (sur,) = a.to_suricata()
    assert (
        sur.tier == "companion"
        and "dns.rcode:3" in sur.text
        and "count 12, seconds 300" in sur.text
    )
