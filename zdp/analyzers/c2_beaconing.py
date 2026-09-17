"""C2 beaconing over ``conn.log`` (spec §2.1).

Implants that check in with a command-and-control server produce outbound
sessions to one destination at near-constant intervals with near-constant
request sizes. We group connections by ``(id.orig_h, id.resp_h, id.resp_p,
proto)`` and score interval regularity, request-size similarity, session
count, and response volume.

ATT&CK: T1071 (Application Layer Protocol), refined to T1071.001 for HTTP/S
and T1071.004 for DNS services; T1095 (Non-Application Layer Protocol) for
ICMP. Tactic: Command and Control.
"""

from __future__ import annotations

import itertools
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from zdp.analyzers.base import BaseAnalyzer
from zdp.models import AnalyzerConfig, Detection, LogWindow, Record
from zdp.policy import format_endpoint
from zdp.rules import (
    TIER_APPROX,
    ExportSkip,
    SuricataRule,
    rule_uuid,
    suricata_sid,
)
from zdp.scoring import (
    coefficient_of_variation,
    deltas,
    median,
    ramp,
    robust_cv,
    validate_weights,
    weighted_score,
)

if TYPE_CHECKING:
    from zdp.config import Config
    from zdp.state import StateStore

NAME = "c2_beaconing"
TACTIC = "Command and Control"

_WEB_SERVICES = frozenset({"http", "ssl", "https", "quic", "spdy"})

GroupKey = tuple[str, str, int, str]


class C2BeaconingAnalyzer(BaseAnalyzer):
    name: ClassVar[str] = NAME
    required_logs: ClassVar[frozenset[str]] = frozenset({"conn"})
    DEFAULTS: ClassVar[Mapping[str, Any]] = {
        "window_seconds": 3600,
        "window_overlap": 0.5,
        "min_confidence": 0.6,
        "min_connections": 8,
        "min_median_interval": 10.0,
        "max_median_interval": 3600.0,
        "suppress_services": ["ntp"],
        "allowlist_categories": ["ntp", "updates", "saas", "monitoring"],
        "keepalive": {"oth_fraction": 0.5, "max_gap_seconds": 1.0},
        "weights": {"interval": 0.45, "bytes": 0.30, "count": 0.15, "resp_volume": 0.10},
        "interval_cv": {"one_at": 0.15, "zero_at": 0.5},
        "bytes_cv": {"one_at": 0.1, "zero_at": 0.6},
        "count_saturation": 48,
        "resp_small_bytes": 2048,
        "resp_small_score": 1.0,
        "resp_large_score": 0.3,
        "export": {"suricata_ports": [80, 443, 8080, 8443]},
    }

    def validate_config(self, config: AnalyzerConfig) -> None:
        validate_weights(config.section("weights"))

    def analyze(self, window: LogWindow) -> list[Detection]:
        cfg = self.config
        groups: dict[GroupKey, list[Record]] = defaultdict(list)
        for rec in window.records("conn"):
            orig, resp, port, proto = (
                rec.get("id.orig_h"),
                rec.get("id.resp_h"),
                rec.get("id.resp_p"),
                rec.get("proto"),
            )
            if not (isinstance(orig, str) and isinstance(resp, str) and isinstance(proto, str)):
                continue
            if not isinstance(port, int):
                continue
            groups[(orig, resp, port, proto)].append(rec)

        detections: list[Detection] = []
        min_conns = cfg.int_param("min_connections")
        for key, conns in groups.items():
            if len(conns) < min_conns:
                continue
            det = self._score_group(key, conns)
            if det is not None:
                detections.append(det)
        return detections

    # -- scoring ----------------------------------------------------------------

    def _passes_static_gates(self, key: GroupKey, conns: Sequence[Record]) -> bool:
        cfg = self.config
        orig, resp, _, _ = key
        # Internal → external only; internal ↔ internal is the lateral detector's domain.
        if not cfg.is_internal(orig) or cfg.is_internal(resp):
            return False
        categories = list(cfg.param("allowlist_categories"))
        if cfg.networks.allowlist_category(resp, categories) is not None:
            return False
        suppressed = {s.lower() for s in cfg.param("suppress_services")}
        return not any(_services(c) & suppressed for c in conns)

    def _is_split_keepalive(self, conns: Sequence[Record]) -> bool:
        """A long-lived session that Zeek split into back-to-back OTH records."""
        settings = self.config.section("keepalive")
        oth = sum(1 for c in conns if c.get("conn_state") == "OTH")
        if oth / len(conns) < float(settings["oth_fraction"]):
            return False
        gaps = []
        for prev, nxt in itertools.pairwise(conns):
            duration = prev.get("duration")
            if not isinstance(duration, (int, float)):
                return False
            gaps.append(nxt["ts"] - (prev["ts"] + duration))
        return bool(gaps) and median(gaps) <= float(settings["max_gap_seconds"])

    def _score_group(self, key: GroupKey, conns: list[Record]) -> Detection | None:
        cfg = self.config
        if not self._passes_static_gates(key, conns):
            return None
        conns = sorted(conns, key=lambda r: r["ts"])
        timestamps = [float(c["ts"]) for c in conns]
        intervals = deltas(timestamps)
        median_interval = median(intervals)
        if not (
            cfg.float_param("min_median_interval")
            <= median_interval
            <= cfg.float_param("max_median_interval")
        ):
            return None
        if self._is_split_keepalive(conns):
            return None

        cv_interval = coefficient_of_variation(intervals)
        cv_mad = robust_cv(intervals)
        cv_candidates = [v for v in (cv_interval, cv_mad) if v is not None]
        if not cv_candidates:
            return None
        cv_score_input = min(cv_candidates)

        orig_bytes = [c.get("orig_bytes") for c in conns]
        sized = [float(b) for b in orig_bytes if isinstance(b, int) and b > 0]
        n_excluded = sum(1 for b in orig_bytes if not isinstance(b, int))
        cv_bytes = coefficient_of_variation(sized) if len(sized) >= 2 else None
        resp_bytes = [float(c["resp_bytes"]) for c in conns if isinstance(c.get("resp_bytes"), int)]
        median_resp = median(resp_bytes) if resp_bytes else None

        interval_ramp = cfg.section("interval_cv")
        bytes_ramp = cfg.section("bytes_cv")
        components = {
            "interval": ramp(cv_score_input, interval_ramp["zero_at"], interval_ramp["one_at"]),
            # Undefined byte dispersion (no sized requests) contributes nothing.
            "bytes": 0.0
            if cv_bytes is None
            else ramp(cv_bytes, bytes_ramp["zero_at"], bytes_ramp["one_at"]),
            "count": min(len(conns) / cfg.float_param("count_saturation"), 1.0),
            "resp_volume": cfg.float_param("resp_small_score")
            if median_resp is not None and median_resp < cfg.float_param("resp_small_bytes")
            else cfg.float_param("resp_large_score"),
        }
        weights = cfg.section("weights")
        confidence = weighted_score(components, weights)
        if confidence < cfg.min_confidence:
            return None

        orig, resp, port, proto = key
        services = sorted(set().union(*(_services(c) for c in conns)))
        technique = _technique(proto, services)
        evidence: dict[str, Any] = {
            "n_conns": len(conns),
            "median_interval": median_interval,
            "cv_interval": cv_interval,
            "cv_mad": cv_mad,
            "cv_score_input": cv_score_input,
            "cv_bytes": cv_bytes,
            "median_orig_bytes": median(sized) if sized else None,
            "median_resp_bytes": median_resp,
            "service": ",".join(services) if services else None,
            "proto": proto,
            "resp_port": port,
            "n_excluded": n_excluded,
            "components": components,
            "weights": dict(weights),
            "window_overlap": cfg.window_overlap,
        }
        return Detection.build(
            ts=timestamps[0],
            last_ts=timestamps[-1],
            detector=NAME,
            src=orig,
            dst=resp,
            indicator=format_endpoint(resp, port),
            confidence=confidence,
            technique_id=technique,
            tactic=TACTIC,
            evidence=evidence,
            uids=(c.get("uid") for c in conns),
        )

    # -- export -----------------------------------------------------------------

    def to_suricata(self) -> list[SuricataRule]:
        """Approximate: per-pair session-count thresholds (no interval regularity)."""
        cfg = self.config
        count = cfg.int_param("min_connections")
        seconds = cfg.window_seconds
        allow: list[str] = []
        for category in cfg.param("allowlist_categories"):
            nets = cfg.networks.allowlists.get(category)
            if nets:
                allow.extend(nets.as_strings())
        dst = (
            "$EXTERNAL_NET"
            if not allow
            else "[$EXTERNAL_NET," + ",".join(f"!{n}" for n in allow) + "]"
        )
        rules = []
        for port in cfg.section("export")["suricata_ports"]:
            signal = f"session_count_tcp_{port}"
            sid = suricata_sid(NAME, signal, cfg.config_hash)
            rule_id = rule_uuid(NAME, signal, cfg.config_hash)
            text = (
                f"alert tcp $HOME_NET any -> {dst} {int(port)} "
                f'(msg:"ZDP c2_beaconing [approx] >= {count} new TCP sessions from one host '
                f'to one destination on port {int(port)} within {seconds}s"; '
                "flow:to_server,not_established; flags:S,CE; "
                f"threshold:type both, track by_both, count {count}, seconds {seconds}; "
                "classtype:trojan-activity; "
                f"metadata:zdp_detector {NAME}, zdp_signal {signal}, zdp_tier {TIER_APPROX}, "
                f"zdp_rule_id {rule_id}, zdp_config_hash {cfg.config_hash}, "
                "mitre_technique_id T1071, mitre_tactic_id TA0011; "
                f"sid:{sid}; rev:1;)"
            )
            rules.append(
                SuricataRule(
                    detector=NAME,
                    signal=signal,
                    tier=TIER_APPROX,
                    sid=sid,
                    text=text,
                    notes=(
                        "Counts session starts per (src, dst) pair; cannot express interval "
                        "regularity or byte-size similarity, and Suricata cannot track by port.",
                    ),
                )
            )
        return rules

    def export_skips(self) -> list[ExportSkip]:
        return [
            ExportSkip(
                detector=NAME,
                signal="beaconing",
                fmt="sigma",
                reason=(
                    "Sigma has no log model for per-flow inter-arrival statistics; interval "
                    "regularity and size dispersion cannot be expressed. Use the Python "
                    "analyzer or the approximate Suricata rules."
                ),
            )
        ]


def _services(rec: Record) -> set[str]:
    raw = rec.get("service")
    if not isinstance(raw, str) or not raw:
        return set()
    return {s.strip().lower() for s in raw.split(",") if s.strip()}


def _technique(proto: str, services: Sequence[str]) -> str:
    if proto.lower() == "icmp":
        return "T1095"
    lowered = {s.lower() for s in services}
    if lowered & _WEB_SERVICES:
        return "T1071.001"
    if "dns" in lowered:
        return "T1071.004"
    return "T1071"


def analyze(
    log_dir: str | Path, config: Config | None = None, state: StateStore | None = None
) -> list[Detection]:
    """Run the C2 beaconing detector over a Zeek log directory."""
    return C2BeaconingAnalyzer.run_on_directory(log_dir, config=config, state=state)
