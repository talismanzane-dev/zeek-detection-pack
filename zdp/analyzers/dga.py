"""Domain-generation-algorithm activity over ``dns.log`` (spec §2.3).

Malware iterating a DGA resolves many machine-generated names until it hits
the one its operator registered, leaving a burst of NXDOMAIN answers for
lexically random second-level labels. Two signals must agree:

* **A — NXDOMAIN burst**: unique *registered* domains answered NXDOMAIN for
  one host inside a sliding 300 s window (dedup by registered domain, so a
  host hammering one dead name scores zero).
* **B — lexical anomaly**: entropy, digit ratio and consonant runs of the
  burst's second-level labels, averaged over the top-K most anomalous.

``confidence = 0.5·c_burst + 0.5·c_lexical`` with a hard gate on
``c_lexical`` — a burst alone never fires.

ATT&CK: T1568.002 (Dynamic Resolution: Domain Generation Algorithms),
tactic Command and Control.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from zdp.analyzers.base import BaseAnalyzer
from zdp.models import AnalyzerConfig, Detection, LogWindow, Record
from zdp.psl import DomainParser, get_parser
from zdp.rules import (
    TIER_APPROX,
    TIER_COMPANION,
    SigmaRule,
    SuricataRule,
    rule_uuid,
    suricata_sid,
)
from zdp.scoring import (
    digit_ratio,
    longest_consonant_run,
    mean,
    ramp,
    shannon_entropy,
    validate_weights,
    weighted_score,
)

if TYPE_CHECKING:
    from zdp.config import Config
    from zdp.state import StateStore

NAME = "dga"
TECHNIQUE = "T1568.002"
TACTIC = "Command and Control"

_Event = tuple[float, str, Record]  # (ts, registered domain, record)


class DGAAnalyzer(BaseAnalyzer):
    name: ClassVar[str] = NAME
    required_logs: ClassVar[frozenset[str]] = frozenset({"dns"})
    DEFAULTS: ClassVar[Mapping[str, Any]] = {
        "window_seconds": 3600,
        "window_overlap": 0.0,
        "min_confidence": 0.6,
        "burst_window_seconds": 300,
        "nx_burst_min": 10,
        "burst_saturation_span": 40,
        "nxdomain_rcodes": ["NXDOMAIN"],
        "min_sld_length": 6,
        "top_k": 20,
        "min_lexical": 0.4,
        "weights": {"burst": 0.5, "lexical": 0.5},
        "lexical_weights": {
            "entropy": 0.7,
            "digit_ratio": 0.15,
            "consonant_run": 0.15,
        },
        "entropy": {"zero_at": 2.8, "one_at": 3.8},
        "digit_ratio": {"zero_at": 0.0, "one_at": 0.3},
        "consonant_run": {"zero_at": 2, "one_at": 5},
        "max_evidence_domains": 20,
    }

    def __init__(self) -> None:
        super().__init__()
        self._parser: DomainParser | None = None

    def validate_config(self, config: AnalyzerConfig) -> None:
        validate_weights(config.section("weights"))
        validate_weights(config.section("lexical_weights"))
        self._parser = get_parser(config.include_psl_private_domains)

    @property
    def parser(self) -> DomainParser:
        if self._parser is None:
            self._parser = get_parser(self.config.include_psl_private_domains)
        return self._parser

    # -- analysis ---------------------------------------------------------------

    def analyze(self, window: LogWindow) -> list[Detection]:
        cfg = self.config
        nx_codes = {c.upper() for c in cfg.param("nxdomain_rcodes")}
        per_host: dict[str, list[_Event]] = defaultdict(list)
        for rec in window.records("dns"):
            rcode, query, orig = rec.get("rcode_name"), rec.get("query"), rec.get("id.orig_h")
            if not (isinstance(rcode, str) and rcode.upper() in nx_codes):
                continue
            if not isinstance(query, str) or not isinstance(orig, str):
                continue
            # Single-label names (Chrome's random intercept probes) and names
            # with no public suffix never count toward a burst.
            registered = self.parser.registered_domain(query)
            if registered is None:
                continue
            if cfg.domains.in_internal_zone(query) or cfg.domains.is_allowlisted(registered, query):
                continue
            per_host[orig].append((float(rec["ts"]), registered, rec))

        detections = []
        for host, events in per_host.items():
            det = self._score_host(host, events)
            if det is not None:
                detections.append(det)
        return detections

    def _best_burst(self, events: list[_Event]) -> tuple[int, int, int]:
        """Sliding window maximizing unique registered domains: (count, lo, hi)."""
        span = self.config.float_param("burst_window_seconds")
        events.sort(key=lambda e: e[0])
        counts: Counter[str] = Counter()
        best = (0, 0, -1)
        lo = 0
        for hi, (ts, domain, _) in enumerate(events):
            counts[domain] += 1
            while ts - events[lo][0] > span:
                old = events[lo][1]
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
                lo += 1
            if len(counts) > best[0]:
                best = (len(counts), lo, hi)
        return best

    def lexical_scores(self, sld: str) -> dict[str, float]:
        cfg = self.config
        entropy = shannon_entropy(sld)
        digits = digit_ratio(sld)
        run = longest_consonant_run(sld)
        components = {
            "entropy": _ramp(cfg, "entropy", entropy),
            "digit_ratio": _ramp(cfg, "digit_ratio", digits),
            "consonant_run": _ramp(cfg, "consonant_run", float(run)),
        }
        return {
            "entropy": entropy,
            "digit_ratio": digits,
            "consonant_run": float(run),
            **{f"c_{k}": v for k, v in components.items()},
            "lexical": weighted_score(components, cfg.section("lexical_weights")),
        }

    def _score_host(self, host: str, events: list[_Event]) -> Detection | None:
        cfg = self.config
        n_unique, lo, hi = self._best_burst(events)
        nx_min = cfg.int_param("nx_burst_min")
        if n_unique < nx_min:
            return None
        burst = events[lo : hi + 1]
        c_burst = min((n_unique - nx_min) / cfg.float_param("burst_saturation_span"), 1.0)

        min_len = cfg.int_param("min_sld_length")
        candidates: list[dict[str, Any]] = []
        excluded_short = excluded_idn = 0
        for registered in dict.fromkeys(domain for _, domain, _ in burst):
            sld = self.parser.split(registered).sld
            if sld.startswith("xn--"):
                excluded_idn += 1
                continue
            if len(sld) < min_len:
                excluded_short += 1
                continue
            candidates.append({"domain": registered, "sld": sld, **self.lexical_scores(sld)})
        candidates.sort(key=lambda c: (-c["lexical"], c["domain"]))
        top = candidates[: cfg.int_param("top_k")]
        c_lexical = mean(c["lexical"] for c in top) if top else 0.0
        if c_lexical < cfg.float_param("min_lexical"):
            return None

        components = {"burst": c_burst, "lexical": c_lexical}
        weights = cfg.section("weights")
        confidence = weighted_score(components, weights)
        if confidence < cfg.min_confidence:
            return None

        evidence: dict[str, Any] = {
            "n_nxdomain_unique": n_unique,
            "n_nxdomain_events": len(burst),
            "burst_start": burst[0][0],
            "burst_end": burst[-1][0],
            "burst_window_seconds": cfg.float_param("burst_window_seconds"),
            "c_burst": c_burst,
            "c_lexical": c_lexical,
            "top_k_used": len(top),
            "n_candidates_scored": len(candidates),
            "n_excluded_short_sld": excluded_short,
            "n_excluded_idn": excluded_idn,
            "components": components,
            "weights": dict(weights),
            "candidates": candidates[: cfg.int_param("max_evidence_domains")],
        }
        return Detection.build(
            ts=burst[0][0],
            last_ts=burst[-1][0],
            detector=NAME,
            src=host,
            dst=None,
            indicator=host,
            confidence=confidence,
            technique_id=TECHNIQUE,
            tactic=TACTIC,
            evidence=evidence,
            uids=(rec.get("uid") for _, _, rec in burst),
        )

    # -- export -----------------------------------------------------------------

    def to_sigma(self) -> list[SigmaRule]:
        from zdp import __release_date__

        cfg = self.config
        h = cfg.config_hash
        nx_min = cfg.int_param("nx_burst_min")
        span_minutes = max(1, round(cfg.float_param("burst_window_seconds") / 60))
        base_name = f"zdp_{NAME}_nxdomain"
        detection: dict[str, Any] = {
            "selection": {"rcode_name": list(cfg.param("nxdomain_rcodes"))},
            "filter_single_label": {"query|re": r"^[^.]+$"},
        }
        if cfg.domains.internal_zones:
            detection["filter_internal_zones"] = {
                "query|endswith": [f".{z}" for z in cfg.domains.internal_zones]
            }
        detection["condition"] = "selection and " + " and ".join(
            f"not {k}" for k in detection if k.startswith("filter_")
        )
        base = {
            "title": "ZDP DGA - NXDOMAIN response (base event)",
            "id": rule_uuid(NAME, "nxdomain", h),
            "name": base_name,
            "status": "experimental",
            "description": (
                "NXDOMAIN answer for a multi-label name outside internal zones. Base event "
                "for the zdp DGA burst correlation; not alerting on its own."
            ),
            "author": "zeek-detection-pack (generated)",
            "date": __release_date__,
            "tags": ["attack.command-and-control", "attack.t1568.002"],
            "logsource": {"category": "dns", "product": "zeek"},
            "detection": detection,
            "falsepositives": ["Typos, stale DNS records, misconfigured search suffixes"],
            "level": "informational",
        }
        correlation = {
            "title": "ZDP DGA - NXDOMAIN burst of distinct names from one host",
            "id": rule_uuid(NAME, "nxdomain_burst", h),
            "status": "experimental",
            "description": (
                f"At least {nx_min} distinct NXDOMAIN query names from one source within "
                f"{span_minutes}m (signal A of zdp's dga analyzer). Approximate: counts "
                "distinct full names rather than registered domains and has no lexical "
                "(signal B) gate, so it is noisier than the Python analyzer."
            ),
            "author": "zeek-detection-pack (generated)",
            "date": __release_date__,
            "tags": ["attack.command-and-control", "attack.t1568.002"],
            "correlation": {
                "type": "value_count",
                "rules": [base_name],
                "group-by": ["id.orig_h"],
                "timespan": f"{span_minutes}m",
                "condition": {"gte": nx_min, "field": "query"},
            },
            "falsepositives": [
                "Browser DNS-interception probes resolved via search suffixes",
                "Hosts with broken resolvers or expired internal zones",
            ],
            "level": "medium",
        }
        return [
            SigmaRule(
                detector=NAME,
                signal="nxdomain_burst",
                tier=TIER_APPROX,
                document=correlation,
                companions=(base,),
            )
        ]

    def to_suricata(self) -> list[SuricataRule]:
        cfg = self.config
        h = cfg.config_hash
        nx_min = cfg.int_param("nx_burst_min")
        seconds = int(cfg.float_param("burst_window_seconds"))
        signal = "nxdomain_rate"
        sid = suricata_sid(NAME, signal, h)
        text = (
            "alert dns any any -> $HOME_NET any "
            f'(msg:"ZDP dga [companion] >= {nx_min} NXDOMAIN responses to one host within '
            f'{seconds}s"; flow:to_client; dns.rcode:3; '
            f"threshold:type both, track by_dst, count {nx_min}, seconds {seconds}; "
            "classtype:bad-unknown; "
            f"metadata:zdp_detector {NAME}, zdp_signal {signal}, zdp_tier {TIER_COMPANION}, "
            f"zdp_rule_id {rule_uuid(NAME, signal, h)}, zdp_config_hash {h}, "
            "mitre_technique_id T1568.002, mitre_tactic_id TA0011; "
            f"sid:{sid}; rev:1;)"
        )
        return [
            SuricataRule(
                detector=NAME,
                signal=signal,
                tier=TIER_COMPANION,
                sid=sid,
                text=text,
                notes=(
                    "NXDOMAIN rate pre-filter; counts responses, not unique registered "
                    "domains, and has no lexical signal. Run alongside the framework.",
                ),
            )
        ]


def _ramp(cfg: AnalyzerConfig, key: str, value: float) -> float:
    section = cfg.section(key)
    return ramp(value, float(section["zero_at"]), float(section["one_at"]))


def analyze(
    log_dir: str | Path, config: Config | None = None, state: StateStore | None = None
) -> list[Detection]:
    """Run the DGA detector over a Zeek log directory."""
    return DGAAnalyzer.run_on_directory(log_dir, config=config, state=state)
