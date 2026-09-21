"""DNS tunneling over ``dns.log`` (spec §2.2).

Tunnels (iodine, dnscat2, DNS-based C2 channels and exfiltration tools)
encode payload in query names and receive data in TXT/NULL/CNAME answers.
Per ``(id.orig_h, registered_domain(query))`` we measure subdomain entropy,
query length, TXT/NULL share, subdomain uniqueness and volume.

ATT&CK: T1071.004 (Application Layer Protocol: DNS), tactic Command and
Control. When both the uniqueness and volume components saturate the
traffic is exfiltration-shaped and evidence carries the secondary technique
T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from zdp.analyzers.base import BaseAnalyzer
from zdp.models import AnalyzerConfig, Detection, LogWindow, Record
from zdp.psl import DomainParser, get_parser
from zdp.rules import TIER_APPROX, SigmaRule, SuricataRule, rule_uuid, suricata_sid
from zdp.scoring import mean, ramp, shannon_entropy, validate_weights, weighted_score

if TYPE_CHECKING:
    from zdp.config import Config
    from zdp.state import StateStore

NAME = "dns_tunneling"
TECHNIQUE = "T1071.004"
TACTIC = "Command and Control"
EXFIL_TECHNIQUE = "T1048.003"
EXFIL_TACTIC = "Exfiltration"


class DNSTunnelingAnalyzer(BaseAnalyzer):
    name: ClassVar[str] = NAME
    required_logs: ClassVar[frozenset[str]] = frozenset({"dns"})
    DEFAULTS: ClassVar[Mapping[str, Any]] = {
        "window_seconds": 3600,
        "window_overlap": 0.0,
        "min_confidence": 0.6,
        "min_queries": 30,
        "min_mean_subdomain_length": 20,
        "weights": {
            "entropy": 0.30,
            "query_length": 0.25,
            "txt_null_ratio": 0.15,
            "unique_subdomain_ratio": 0.15,
            "volume": 0.15,
        },
        "entropy": {"zero_at": 3.0, "one_at": 4.0},
        "query_length": {"zero_at": 40, "one_at": 80},
        "txt_null_ratio": {"zero_at": 0.05, "one_at": 0.4},
        "unique_subdomain_ratio": {"zero_at": 0.5, "one_at": 0.95},
        "volume": {"zero_at": 30, "one_at": 300},
        "txt_null_types": ["TXT", "NULL"],
        "half_weight_types": ["CNAME"],
        "half_weight": 0.5,
        "exfil_component_threshold": 0.9,
        "exclude_qtypes": ["SRV"],
        "exclude_underscore_labels": True,
        "qps_bucket_seconds": 60,
        "sample_queries": 3,
        "sample_max_length": 120,
    }

    def __init__(self) -> None:
        super().__init__()
        self._parser: DomainParser | None = None

    def validate_config(self, config: AnalyzerConfig) -> None:
        validate_weights(config.section("weights"))
        self._parser = get_parser(config.include_psl_private_domains)

    @property
    def parser(self) -> DomainParser:
        if self._parser is None:
            self._parser = get_parser(self.config.include_psl_private_domains)
        return self._parser

    def analyze(self, window: LogWindow) -> list[Detection]:
        cfg = self.config
        exclude_qtypes = {q.upper() for q in cfg.param("exclude_qtypes")}
        exclude_underscore = bool(cfg.param("exclude_underscore_labels"))
        groups: dict[tuple[str, str], list[tuple[Record, str]]] = defaultdict(list)
        for rec in window.records("dns"):
            query, orig = rec.get("query"), rec.get("id.orig_h")
            if not isinstance(query, str) or not query or not isinstance(orig, str):
                continue
            qtype = rec.get("qtype_name")
            if isinstance(qtype, str) and qtype.upper() in exclude_qtypes:
                continue
            if exclude_underscore and any(label.startswith("_") for label in query.split(".")):
                continue  # AD/Kerberos service discovery (_ldap._tcp…)
            registered = self.parser.registered_domain(query)
            if registered is None or cfg.domains.is_allowlisted(registered, query):
                continue
            groups[(orig, registered)].append((rec, query))

        detections = []
        for (orig, registered), items in groups.items():
            det = self._score_group(orig, registered, items)
            if det is not None:
                detections.append(det)
        return detections

    def _score_group(
        self, orig: str, registered: str, items: list[tuple[Record, str]]
    ) -> Detection | None:
        cfg = self.config
        n = len(items)
        if n < cfg.int_param("min_queries"):
            return None
        subdomains = [_strip_registered(q, registered) for _, q in items]
        mean_sub_len = mean(len(s) for s in subdomains)
        if mean_sub_len < cfg.float_param("min_mean_subdomain_length"):
            return None

        qtypes = Counter(
            (rec.get("qtype_name") or "-") if isinstance(rec.get("qtype_name"), str) else "-"
            for rec, _ in items
        )
        full_types = {t.upper() for t in cfg.param("txt_null_types")}
        half_types = {t.upper() for t in cfg.param("half_weight_types")}
        weighted_txt = sum(
            c for t, c in qtypes.items() if t.upper() in full_types
        ) + cfg.float_param("half_weight") * sum(
            c for t, c in qtypes.items() if t.upper() in half_types
        )

        bucket = cfg.float_param("qps_bucket_seconds")
        buckets = Counter(int(float(rec["ts"]) // bucket) for rec, _ in items)
        metrics = {
            "mean_entropy": mean(shannon_entropy(s.replace(".", "")) for s in subdomains),
            "mean_qlen": mean(len(q) for _, q in items),
            "txt_null_ratio": weighted_txt / n,
            "unique_sub_ratio": len(set(subdomains)) / n,
            "qps_peak": max(buckets.values()),
        }
        components = {
            "entropy": _ramp(cfg, "entropy", metrics["mean_entropy"]),
            "query_length": _ramp(cfg, "query_length", metrics["mean_qlen"]),
            "txt_null_ratio": _ramp(cfg, "txt_null_ratio", metrics["txt_null_ratio"]),
            "unique_subdomain_ratio": _ramp(
                cfg, "unique_subdomain_ratio", metrics["unique_sub_ratio"]
            ),
            "volume": _ramp(cfg, "volume", float(n)),
        }
        weights = cfg.section("weights")
        confidence = weighted_score(components, weights)
        if confidence < cfg.min_confidence:
            return None

        limit, max_len = cfg.int_param("sample_queries"), cfg.int_param("sample_max_length")
        samples: list[str] = []
        for _, q in items:
            if q not in samples:
                samples.append(q)
            if len(samples) == limit:
                break
        threshold = cfg.float_param("exfil_component_threshold")
        secondary = (
            [{"technique_id": EXFIL_TECHNIQUE, "tactic": EXFIL_TACTIC}]
            if components["unique_subdomain_ratio"] >= threshold
            and components["volume"] >= threshold
            else []
        )
        timestamps = [float(rec["ts"]) for rec, _ in items]
        evidence: dict[str, Any] = {
            **metrics,
            "n_queries": n,
            "mean_subdomain_length": mean_sub_len,
            "qtype_histogram": dict(qtypes),
            "sample_queries": [s[:max_len] for s in samples],
            "registered_domain": registered,
            "components": components,
            "weights": dict(weights),
            "secondary_techniques": secondary,
        }
        return Detection.build(
            ts=min(timestamps),
            last_ts=max(timestamps),
            detector=NAME,
            src=orig,
            dst=None,
            indicator=registered,
            confidence=confidence,
            technique_id=TECHNIQUE,
            tactic=TACTIC,
            evidence=evidence,
            uids=(rec.get("uid") for rec, _ in items),
        )

    # -- export -----------------------------------------------------------------

    def _filters(self) -> dict[str, Any]:
        cfg = self.config
        filters: dict[str, Any] = {"filter_reverse": {"query|endswith": ".arpa"}}
        if cfg.param("exclude_underscore_labels"):
            filters["filter_service_discovery"] = {"query|re": r"(^|\.)_"}
        if cfg.param("exclude_qtypes"):
            filters["filter_qtypes"] = {"qtype_name": list(cfg.param("exclude_qtypes"))}
        return filters

    def to_sigma(self) -> list[SigmaRule]:
        cfg = self.config
        h = cfg.config_hash
        long_len = int(cfg.section("query_length")["one_at"])
        txt_len = int(cfg.section("query_length")["zero_at"])
        min_queries = cfg.int_param("min_queries")
        window = f"{cfg.window_seconds // 60}m"
        filters = self._filters()
        condition_filters = " and ".join(f"not {name}" for name in filters)
        base_name = f"zdp_{NAME}_suspicious_query"
        base = {
            "title": "ZDP DNS tunneling - long or TXT/NULL query (base event)",
            "id": rule_uuid(NAME, "suspicious_query", h),
            "name": base_name,
            "status": "experimental",
            "description": (
                "Single DNS query that is either very long or a long TXT/NULL query. "
                "Base event for the zdp DNS tunneling correlation; not alerting on its own. "
                f"Thresholds derived from zdp config {h}."
            ),
            "author": "zeek-detection-pack (generated)",
            "date": _release_date(),
            "tags": [
                "attack.command-and-control",
                "attack.t1071.004",
            ],
            "logsource": {"category": "dns", "product": "zeek"},
            "detection": {
                "selection_long": {"query|re": f"^.{{{long_len},}}$"},
                "selection_txt_null": {
                    "qtype_name": list(cfg.param("txt_null_types")),
                    "query|re": f"^.{{{txt_len},}}$",
                },
                **filters,
                "condition": f"(selection_long or selection_txt_null) and {condition_filters}",
            },
            "falsepositives": [
                "CDN cache-busting hostnames and EDR/AV hash lookups (allowlist the vendor domain)",
                "DNSBL reputation lookups by mail gateways",
            ],
            "level": "informational",
        }
        correlation = {
            "title": "ZDP DNS tunneling - sustained long/TXT query volume from one host",
            "id": rule_uuid(NAME, "query_volume", h),
            "status": "experimental",
            "description": (
                f"At least {min_queries} long or TXT/NULL DNS queries from one source within "
                f"{window}. Approximates zdp's dns_tunneling analyzer: it cannot group by "
                "registered domain (no PSL in Sigma) or score subdomain entropy/uniqueness."
            ),
            "author": "zeek-detection-pack (generated)",
            "date": _release_date(),
            "tags": [
                "attack.command-and-control",
                "attack.t1071.004",
                "attack.exfiltration",
                "attack.t1048.003",
            ],
            "correlation": {
                "type": "event_count",
                "rules": [base_name],
                "group-by": ["id.orig_h"],
                "timespan": window,
                "condition": {"gte": min_queries},
            },
            "falsepositives": ["Mail servers performing DNSBL lookups; SaaS agents using TXT"],
            "level": "medium",
        }
        return [
            SigmaRule(
                detector=NAME,
                signal="query_volume",
                tier=TIER_APPROX,
                document=correlation,
                companions=(base,),
            )
        ]

    def to_suricata(self) -> list[SuricataRule]:
        cfg = self.config
        h = cfg.config_hash
        long_len = int(cfg.section("query_length")["one_at"])
        count = cfg.int_param("min_queries")
        seconds = cfg.window_seconds
        exclusions = 'content:!".arpa"; endswith; '
        if cfg.param("exclude_underscore_labels"):
            exclusions += 'pcre:!"/(^|\\x2e)_/"; '
        rules = []
        specs = [
            (
                "long_query",
                f'dns.query; pcre:"/^.{{{long_len},}}$/"; {exclusions}',
                f"long DNS query names (>= {long_len} chars)",
            ),
        ]
        rrtypes = {"TXT": 16, "NULL": 10}
        for qtype in cfg.param("txt_null_types"):
            code = rrtypes.get(str(qtype).upper())
            if code is not None:
                specs.append(
                    (
                        f"{str(qtype).lower()}_rate",
                        f"dns.rrtype:{code}; dns.query; {exclusions}",
                        f"{qtype} queries",
                    )
                )
        for signal, match, label in specs:
            sid = suricata_sid(NAME, signal, h)
            text = (
                "alert dns $HOME_NET any -> any any "
                f'(msg:"ZDP dns_tunneling [approx] >= {count} {label} from one host '
                f'within {seconds}s"; flow:to_server; {match}'
                f"threshold:type both, track by_src, count {count}, seconds {seconds}; "
                "classtype:policy-violation; "
                f"metadata:zdp_detector {NAME}, zdp_signal {signal}, zdp_tier {TIER_APPROX}, "
                f"zdp_rule_id {rule_uuid(NAME, signal, h)}, zdp_config_hash {h}, "
                "mitre_technique_id T1071.004, mitre_tactic_id TA0011; "
                f"sid:{sid}; rev:1;)"
            )
            rules.append(
                SuricataRule(
                    detector=NAME,
                    signal=signal,
                    tier=TIER_APPROX,
                    sid=sid,
                    text=text,
                    notes=("Per-source rate only; no registered-domain grouping or entropy.",),
                )
            )
        return rules


def _strip_registered(query: str, registered: str) -> str:
    if query == registered:
        return ""
    return query[: -(len(registered) + 1)] if query.endswith("." + registered) else query


def _ramp(cfg: AnalyzerConfig, key: str, value: float) -> float:
    section = cfg.section(key)
    return ramp(value, float(section["zero_at"]), float(section["one_at"]))


def _release_date() -> str:
    from zdp import __release_date__

    return __release_date__


def analyze(
    log_dir: str | Path, config: Config | None = None, state: StateStore | None = None
) -> list[Detection]:
    """Run the DNS tunneling detector over a Zeek log directory."""
    return DNSTunnelingAnalyzer.run_on_directory(log_dir, config=config, state=state)
