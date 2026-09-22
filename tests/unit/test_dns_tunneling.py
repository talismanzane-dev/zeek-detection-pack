"""DNS tunneling analyzer (spec §2.2, §7.2)."""

from __future__ import annotations

import base64
import random

import pytest

from tests.conftest import T0, configure, dns, window
from zdp.analyzers.dns_tunneling import DNSTunnelingAnalyzer
from zdp.config import Config
from zdp.scoring import weighted_score

SRC = "10.1.3.22"


def b32(rng: random.Random, n: int) -> str:
    return base64.b32encode(rng.randbytes(n)).decode().rstrip("=").lower()


def tunnel(
    n: int = 120, qtype: str = "TXT", domain: str = "t.example.net", size: int = 60, src: str = SRC
) -> list[dict[str, object]]:
    rng = random.Random(n)
    return [dns(T0 + 10 * i, src, f"{b32(rng, size)}.{domain}", qtype) for i in range(n)]


@pytest.fixture
def analyzer(config: Config) -> DNSTunnelingAnalyzer:
    return configure(DNSTunnelingAnalyzer(), config)  # type: ignore[return-value]


def test_txt_tunnel_detected(analyzer: DNSTunnelingAnalyzer) -> None:
    (det,) = analyzer.analyze(window(dns=tunnel()))
    assert det.indicator == "example.net"  # grouped at the registered domain
    assert det.dst is None
    assert det.technique_id == "T1071.004"
    ev = det.evidence
    for key in (
        "mean_entropy",
        "mean_qlen",
        "txt_null_ratio",
        "unique_sub_ratio",
        "qps_peak",
        "n_queries",
        "qtype_histogram",
        "sample_queries",
    ):
        assert key in ev
    assert ev["qtype_histogram"] == {"TXT": 120}
    assert len(ev["sample_queries"]) == 3 and all(len(q) <= 120 for q in ev["sample_queries"])
    assert det.confidence == pytest.approx(
        weighted_score(ev["components"], ev["weights"]), abs=1e-4
    )
    assert ev["secondary_techniques"] == []  # volume component not saturated at 120 queries


def test_exfil_shaped_volume_adds_secondary_technique(analyzer: DNSTunnelingAnalyzer) -> None:
    (det,) = analyzer.analyze(window(dns=tunnel(n=320)))
    assert det.evidence["secondary_techniques"] == [
        {"tactic": "Exfiltration", "technique_id": "T1048.003"}
    ]


def test_cname_counts_half(analyzer: DNSTunnelingAnalyzer) -> None:
    (det,) = analyzer.analyze(window(dns=tunnel(qtype="CNAME")))
    assert det.evidence["txt_null_ratio"] == pytest.approx(0.5)


@pytest.mark.parametrize(
    ("records", "reason"),
    [
        (tunnel(n=29), "below min_queries"),
        (tunnel(size=5), "mean subdomain shorter than 20"),
        (tunnel(domain="mail.google.com"), "allowlisted registered domain"),
        (tunnel(qtype="SRV"), "SRV excluded"),
        (tunnel(domain="_ldap._tcp.dc.corp.example.org"), "underscore service labels excluded"),
    ],
)
def test_gates_and_exclusions(
    analyzer: DNSTunnelingAnalyzer, records: list[dict[str, object]], reason: str
) -> None:
    assert analyzer.analyze(window(dns=records)) == [], reason


def test_cdn_cache_busting_scores_below_threshold(analyzer: DNSTunnelingAnalyzer) -> None:
    rng = random.Random(9)
    records = [
        dns(T0 + 5 * i, SRC, f"{rng.randbytes(8).hex()}.assets.example.org") for i in range(400)
    ]
    assert analyzer.analyze(window(dns=records)) == []


def test_psl_grouping_splits_private_suffix_tenants(analyzer: DNSTunnelingAnalyzer) -> None:
    # Each <tenant>.s3.amazonaws.com is its own registered domain, so 40 tenants
    # with one query each never form a 30-query group.
    rng = random.Random(4)
    records = [dns(T0 + i, SRC, f"{b32(rng, 30)}.t{i}.s3.amazonaws.com", "TXT") for i in range(40)]
    assert analyzer.analyze(window(dns=records)) == []


def test_exports_are_parameterized(config: Config) -> None:
    a = configure(DNSTunnelingAnalyzer(), config, min_queries=55)
    (sigma,) = a.to_sigma()
    assert sigma.document["correlation"]["condition"] == {"gte": 55}
    assert sigma.companions[0]["detection"]["selection_long"] == {"query|re": "^.{80,}$"}
    assert all("count 55" in r.text for r in a.to_suricata())
