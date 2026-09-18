"""C2 beaconing analyzer (spec §2.1, §7.1)."""

from __future__ import annotations

import random

import pytest

from tests.conftest import T0, configure, conn, window
from zdp.analyzers.c2_beaconing import C2BeaconingAnalyzer
from zdp.config import Config
from zdp.scoring import weighted_score

SRC, DST = "10.1.2.15", "203.0.113.40"
SPEC_EVIDENCE = {
    "n_conns",
    "median_interval",
    "cv_interval",
    "cv_mad",
    "cv_bytes",
    "median_orig_bytes",
    "median_resp_bytes",
    "service",
}


def beacon(
    n: int = 40,
    interval: float = 60.0,
    jitter: float = 0.0,
    *,
    src: str = SRC,
    dst: str = DST,
    port: int = 443,
    proto: str = "tcp",
    service: str | None = "ssl",
    orig_bytes: int = 900,
    conn_state: str = "SF",
    duration: float = 0.3,
) -> list[dict[str, object]]:
    rng = random.Random(1)
    t = T0 + 5
    out = []
    for _ in range(n):
        out.append(
            conn(
                t,
                src,
                dst,
                port,
                service=service,
                proto=proto,
                orig_bytes=orig_bytes,
                resp_bytes=300,
                conn_state=conn_state,
                duration=duration,
            )
        )
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return out


@pytest.fixture
def analyzer(config: Config) -> C2BeaconingAnalyzer:
    a = C2BeaconingAnalyzer()
    configure(a, config)
    return a


def test_regular_beacon_detected_with_auditable_evidence(analyzer: C2BeaconingAnalyzer) -> None:
    (det,) = analyzer.analyze(window(conn=beacon(jitter=0.05)))
    assert (det.src, det.dst, det.indicator) == (SRC, DST, "203.0.113.40:443")
    assert det.technique_id == "T1071.001" and det.tactic == "Command and Control"
    assert det.severity == "high"
    assert det.evidence.keys() >= SPEC_EVIDENCE
    # Every value used in scoring is present: recompute confidence from evidence.
    recomputed = weighted_score(det.evidence["components"], det.evidence["weights"])
    assert det.confidence == pytest.approx(recomputed, abs=1e-4)
    assert det.evidence["cv_score_input"] == min(
        det.evidence["cv_interval"], det.evidence["cv_mad"]
    )
    assert len(det.uids) == 40


@pytest.mark.parametrize(
    ("records", "reason"),
    [
        (beacon(n=7), "fewer than min_connections"),
        (beacon(interval=5.0), "median interval below 10 s"),
        (beacon(dst="10.1.5.20"), "internal destination"),
        (beacon(src="198.51.100.7"), "external source"),
        (beacon(service="ntp", port=123, proto="udp"), "ntp service suppressed"),
        (beacon(dst="216.239.35.0"), "allowlisted NTP destination"),
    ],
)
def test_hard_gates(
    analyzer: C2BeaconingAnalyzer, records: list[dict[str, object]], reason: str
) -> None:
    assert analyzer.analyze(window(conn=records)) == [], reason


def test_split_keepalive_suppressed(analyzer: C2BeaconingAnalyzer) -> None:
    records = beacon(interval=30.0, conn_state="OTH", duration=29.95, orig_bytes=64)
    assert analyzer.analyze(window(conn=records)) == []


def test_poisson_traffic_not_detected(analyzer: C2BeaconingAnalyzer) -> None:
    rng = random.Random(3)
    t, records = T0, []
    while t < T0 + 3500:
        records.append(
            conn(
                t,
                SRC,
                DST,
                443,
                service="ssl",
                orig_bytes=int(rng.lognormvariate(7, 1)),
                resp_bytes=5000,
            )
        )
        t += rng.expovariate(1 / 60)
    assert analyzer.analyze(window(conn=records)) == []


def test_mad_cv_rescues_a_missed_checkin(analyzer: C2BeaconingAnalyzer) -> None:
    records = beacon(n=13, interval=270.0, jitter=0.02)
    del records[6]  # host asleep for one interval
    (det,) = analyzer.analyze(window(conn=records))
    assert det.evidence["cv_mad"] < det.evidence["cv_interval"]
    assert det.evidence["components"]["interval"] == 1.0


def test_unset_byte_counts_excluded_and_counted(analyzer: C2BeaconingAnalyzer) -> None:
    records = beacon()
    for rec in records[:5]:
        rec["orig_bytes"] = None
    (det,) = analyzer.analyze(window(conn=records))
    assert det.evidence["n_excluded"] == 5


@pytest.mark.parametrize(
    ("proto", "service", "technique"),
    [
        ("tcp", "ssl", "T1071.001"),
        ("tcp", "http", "T1071.001"),
        ("udp", "dns", "T1071.004"),
        ("tcp", None, "T1071"),
        ("icmp", None, "T1095"),
    ],
)
def test_technique_refinement(
    analyzer: C2BeaconingAnalyzer, proto: str, service: str | None, technique: str
) -> None:
    (det,) = analyzer.analyze(window(conn=beacon(proto=proto, service=service, port=8)))
    assert det.technique_id == technique


def test_ipv6_indicator(analyzer: C2BeaconingAnalyzer) -> None:
    (det,) = analyzer.analyze(window(conn=beacon(src="fd00::25", dst="2001:db8:40::10", port=8443)))
    assert det.indicator == "[2001:db8:40::10]:8443"


def test_suricata_export_tracks_config(config: Config) -> None:
    a = configure(C2BeaconingAnalyzer(), config, min_connections=12)
    rules = a.to_suricata()
    assert len(rules) == 4
    assert all("count 12, seconds 3600" in r.text and "zdp_tier approx" in r.text for r in rules)
    assert [s.fmt for s in a.export_skips()] == ["sigma"]
