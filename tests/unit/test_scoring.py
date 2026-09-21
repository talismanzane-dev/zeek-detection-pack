"""Scoring helpers tested with synthetic metric inputs (spec §4.5)."""

from __future__ import annotations

import math

import pytest

from zdp.scoring import (
    coefficient_of_variation,
    deltas,
    digit_ratio,
    longest_consonant_run,
    mad,
    ramp,
    reduce_severity,
    robust_cv,
    severity_for,
    shannon_entropy,
    validate_weights,
    weighted_score,
)


class TestRamp:
    def test_decreasing_ramp_matches_beacon_interval_spec(self) -> None:
        # "c = 1.0 if CV < 0.12; linear falloff to 0.0 at CV >= 0.5"
        assert ramp(0.10, zero_at=0.5, one_at=0.12) == 1.0
        assert ramp(0.12, zero_at=0.5, one_at=0.12) == 1.0
        assert ramp(0.5, zero_at=0.5, one_at=0.12) == 0.0
        assert ramp(0.9, zero_at=0.5, one_at=0.12) == 0.0
        assert ramp(0.31, zero_at=0.5, one_at=0.12) == pytest.approx(0.5)

    def test_increasing_ramp_matches_entropy_spec(self) -> None:
        # "0 at <= 3.0 bits/char, 1.0 at >= 4.0, linear between"
        assert ramp(2.5, 3.0, 4.0) == 0.0
        assert ramp(3.0, 3.0, 4.0) == 0.0
        assert ramp(3.5, 3.0, 4.0) == pytest.approx(0.5)
        assert ramp(4.0, 3.0, 4.0) == 1.0
        assert ramp(4.8, 3.0, 4.0) == 1.0

    def test_nan_and_equal_anchors(self) -> None:
        assert ramp(math.nan, 0.0, 1.0) == 0.0
        with pytest.raises(ValueError):
            ramp(1.0, 2.0, 2.0)


class TestWeightedScore:
    def test_sum_of_weighted_components(self) -> None:
        weights = {"a": 0.45, "b": 0.30, "c": 0.15, "d": 0.10}
        components = {"a": 1.0, "b": 0.5, "c": 0.0, "d": 1.0}
        assert weighted_score(components, weights) == pytest.approx(0.45 + 0.15 + 0.10)

    def test_rejects_weights_not_summing_to_one(self) -> None:
        with pytest.raises(ValueError, match=r"sum to 1\.0"):
            weighted_score({"a": 1.0, "b": 1.0}, {"a": 0.6, "b": 0.6})

    def test_rejects_out_of_range_or_missing_components(self) -> None:
        with pytest.raises(ValueError, match="outside"):
            weighted_score({"a": 1.2}, {"a": 1.0})
        with pytest.raises(ValueError, match="missing"):
            weighted_score({}, {"a": 1.0})

    def test_validate_weights_rejects_negative(self) -> None:
        with pytest.raises(ValueError):
            validate_weights({"a": 1.5, "b": -0.5})


class TestSeverity:
    @pytest.mark.parametrize(
        ("confidence", "severity"),
        [
            (0.0, "low"),
            (0.59, "low"),
            (0.6, "medium"),
            (0.849, "medium"),
            (0.85, "high"),
            (1, "high"),
        ],
    )
    def test_bands(self, confidence: float, severity: str) -> None:
        assert severity_for(confidence) == severity

    def test_reduce(self) -> None:
        assert reduce_severity("high") == "medium"
        assert reduce_severity("medium") == "low"
        assert reduce_severity("low") == "low"


class TestDispersion:
    def test_cv_of_constant_series_is_zero(self) -> None:
        assert coefficient_of_variation([60.0] * 10) == 0.0

    def test_cv_undefined_cases(self) -> None:
        assert coefficient_of_variation([1.0]) is None
        assert coefficient_of_variation([0.0, 0.0]) is None
        assert robust_cv([5.0]) is None

    def test_robust_cv_resists_a_single_gap(self) -> None:
        # Regular 300 s check-ins with one missed beacon (600 s gap).
        intervals = [300.0] * 11 + [600.0]
        cv = coefficient_of_variation(intervals)
        rcv = robust_cv(intervals)
        assert cv is not None and rcv is not None
        assert cv > 0.25
        assert rcv == 0.0  # MAD ignores the single outlier

    def test_mad(self) -> None:
        assert mad([1.0, 2.0, 3.0, 4.0, 100.0]) == 1.0

    def test_deltas(self) -> None:
        assert deltas([0.0, 60.0, 125.0]) == [60.0, 65.0]


class TestLexical:
    def test_entropy(self) -> None:
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("ab") == pytest.approx(1.0)
        assert shannon_entropy("abcdefghijklmnop") == pytest.approx(4.0)

    def test_base32_payload_exceeds_english(self) -> None:
        assert shannon_entropy("mfrggzdfmztwq2lknnwg23tpobyxe43u") > 3.8
        assert shannon_entropy("thequickbrownfox") < shannon_entropy("x7k2pq9zv4m1b8nw")

    def test_digit_ratio_and_consonant_run(self) -> None:
        assert digit_ratio("ab12") == 0.5
        assert digit_ratio("") == 0.0
        assert longest_consonant_run("strengths") == 5  # n-g-t-h-s: why its weight is small
        assert longest_consonant_run("xkcdqwrtz") == 9
        assert longest_consonant_run("rhythm") == 3  # y is a vowel: "rh", "thm"
