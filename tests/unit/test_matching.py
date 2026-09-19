"""Detection ↔ label matching rules (spec §4.3) and metric edge cases (§4.4)."""

from __future__ import annotations

from typing import Any

import pytest

from zdp.harness.labels import Label, LabelError, parse_labels
from zdp.harness.matching import Counts, detection_matches, indicator_matches, match
from zdp.models import Detection


def det(**kw: Any) -> Detection:
    base: dict[str, Any] = {
        "ts": 1000.0,
        "last_ts": 2000.0,
        "detector": "dns_tunneling",
        "src": "10.0.0.1",
        "dst": None,
        "indicator": "example.net",
        "confidence": 0.9,
        "technique_id": "T1071.004",
        "tactic": "Command and Control",
        "evidence": {},
        "uids": [],
    }
    base.update(kw)
    return Detection.build(**base)


def label(**kw: Any) -> Label:
    base: dict[str, Any] = {
        "detector": "dns_tunneling",
        "src": "10.0.0.1",
        "window": (1500.0, 1600.0),
    }
    base.update(kw)
    return Label(**base)


class TestDetectionMatches:
    def test_detector_and_src_must_agree(self) -> None:
        assert detection_matches(det(), label())
        assert not detection_matches(det(detector="dga"), label())
        assert not detection_matches(det(src="10.0.0.2"), label())

    def test_dst_only_checked_when_labeled(self) -> None:
        assert detection_matches(det(dst="203.0.113.1"), label())
        assert not detection_matches(det(dst="203.0.113.1"), label(dst="203.0.113.2"))
        assert detection_matches(det(dst="203.0.113.1"), label(dst="203.0.113.1"))

    def test_indicator_case_insensitive_and_registered_domain(self) -> None:
        assert indicator_matches("Example.NET", "example.net")
        assert indicator_matches("t.example.net", "example.net")  # registered-domain level
        assert indicator_matches("a.example.co.uk", "b.example.co.uk")
        assert not indicator_matches("example.net", "example.org")
        assert not indicator_matches("203.0.113.1:443", "203.0.113.1:80")
        assert detection_matches(det(indicator="T.EXAMPLE.net"), label(indicator="example.net"))

    def test_temporal_overlap_with_tolerance(self) -> None:
        lbl = label(window=(3000.0, 3100.0))
        assert not detection_matches(det(ts=1000.0, last_ts=2879.0), lbl)
        assert detection_matches(det(ts=1000.0, last_ts=2880.0), lbl)  # within 120 s
        assert detection_matches(det(ts=3220.0, last_ts=3300.0), lbl)
        assert not detection_matches(det(ts=3221.0, last_ts=3300.0), lbl)
        assert not detection_matches(det(ts=1000.0, last_ts=2880.0), lbl, tolerance=0.0)


class TestGreedyAssignment:
    def test_highest_confidence_claims_first_and_duplicates_ignored(self) -> None:
        low, high = det(confidence=0.7), det(confidence=0.95, ts=1100.0)
        result = match([low, high], [label()])
        assert [d for d, _ in result.true_positives] == [high]
        assert [d for d, _ in result.duplicates] == [low]
        assert result.counts() == Counts(tp=1, fp=0, fn=0, duplicates=1)

    def test_strict_policy_counts_duplicates_as_fp(self) -> None:
        result = match([det(confidence=0.7), det(confidence=0.95)], [label()], dedup_policy="fp")
        assert result.counts() == Counts(tp=1, fp=1, fn=0, duplicates=0)

    def test_one_to_one_assignment_over_two_labels(self) -> None:
        labels = [label(window=(1500.0, 1600.0)), label(window=(1700.0, 1800.0))]
        result = match([det(confidence=0.9), det(confidence=0.8)], labels)
        assert result.counts() == Counts(tp=2, fp=0, fn=0)

    def test_unmatched_become_fp_and_fn(self) -> None:
        result = match([det(src="10.0.0.9")], [label()])
        assert result.counts() == Counts(tp=0, fp=1, fn=1)

    def test_invalid_policy(self) -> None:
        with pytest.raises(ValueError):
            match([], [], dedup_policy="maybe")


class TestMetrics:
    def test_zero_denominators_are_flagged(self) -> None:
        m = Counts().metrics()
        assert m["precision"] == m["recall"] == m["f1"] == 0.0
        assert m["undefined"] == ["precision", "recall", "f1"]

    def test_only_false_negatives(self) -> None:
        m = Counts(fn=3).metrics()
        assert m["undefined"] == ["precision", "f1"]
        assert m["recall"] == 0.0

    def test_formula(self) -> None:
        c = Counts(tp=3, fp=1, fn=2)
        m = c.metrics()
        p, r = c.tp / (c.tp + c.fp), c.tp / (c.tp + c.fn)
        assert m["precision"] == p and m["recall"] == r
        assert m["f1"] == pytest.approx(2 * p * r / (p + r))


class TestLabelSchema:
    def test_parse_valid(self) -> None:
        ls = parse_labels(
            {
                "schema_version": 1,
                "labels": [
                    {"detector": "dga", "src": "10.0.0.1", "window": [1, 2]},
                    {
                        "detector": "c2_beaconing",
                        "src": "fd00::0:1",
                        "dst": "2001:db8::1",
                        "indicator": "[2001:db8::1]:443",
                        "window": [1, 2],
                        "technique_id": "T1071",
                    },
                ],
            }
        )
        assert ls.labels[1].src == "fd00::1"
        assert not ls.is_pure_negative

    @pytest.mark.parametrize(
        "bad",
        [
            {"schema_version": 2, "labels": []},
            {"schema_version": 1},
            {"schema_version": 1, "labels": [{"detector": "dga", "src": "10.0.0.1"}]},
            {"schema_version": 1, "labels": [{"detector": "dga", "src": "nope", "window": [1, 2]}]},
            {
                "schema_version": 1,
                "labels": [{"detector": "dga", "src": "10.0.0.1", "window": [2, 1]}],
            },
            {
                "schema_version": 1,
                "labels": [
                    {"detector": "dga", "src": "10.0.0.1", "window": [1, 2], "colour": "red"}
                ],
            },
        ],
    )
    def test_rejects_invalid(self, bad: dict[str, Any]) -> None:
        with pytest.raises(LabelError):
            parse_labels(bad, "s")

    def test_empty_labels_is_pure_negative(self) -> None:
        assert parse_labels({"schema_version": 1, "labels": []}).is_pure_negative
