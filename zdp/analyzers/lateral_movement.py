"""Lateral movement over ``conn.log`` + ``smb_files.log`` (spec §2.4).

Three sub-signals, each able to emit on its own:

1. **New internal admin-service pair** — an at-least-partially established
   internal→internal session on an admin port (SMB, RPC, RDP, WinRM, SSH)
   for an ``(orig_h, resp_h, resp_p)`` tuple absent from the baseline.
   Requires a baseline at least 7 days old; during warm-up it emits nothing.
2. **Admin-share file activity** — writes to, or executables on,
   ``ADMIN$`` / ``C$`` / drive shares (PsExec-style tool staging).
3. **Fan-out** — one host touching many internal hosts on admin ports within
   10 minutes; mostly-failed attempts are tagged ``pattern: scan`` and mapped
   to T1046 (Discovery) at reduced severity.

Signals 1 and 2 on the same ``(orig_h, resp_h)`` within 10 minutes merge into
one detection with ``confidence = min(c₁ + 0.5·c₂, 1)``.

ATT&CK: T1021.002 (SMB/Windows Admin Shares), T1021.001 (RDP), T1021.003
(DCOM/RPC), T1021.004 (SSH), T1021.006 (WinRM) by port; T1046 for scans.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from zdp.analyzers.base import BaseAnalyzer
from zdp.models import AnalyzerConfig, Detection, LogWindow, Record
from zdp.policy import format_endpoint
from zdp.rules import (
    TIER_APPROX,
    TIER_FULL,
    ExportSkip,
    SigmaRule,
    SuricataRule,
    rule_uuid,
    suricata_sid,
)
from zdp.scoring import reduce_severity, severity_for

if TYPE_CHECKING:
    from zdp.config import Config
    from zdp.state import StateStore

NAME = "lateral_movement"
TACTIC = "Lateral Movement"
SCAN_TECHNIQUE = "T1046"
SCAN_TACTIC = "Discovery"
DAY = 86_400.0

#: Admin-service port → ATT&CK sub-technique of T1021 (Remote Services).
PORT_TECHNIQUES: Mapping[int, str] = {
    445: "T1021.002",
    139: "T1021.002",
    3389: "T1021.001",
    135: "T1021.003",
    22: "T1021.004",
    5985: "T1021.006",
    5986: "T1021.006",
}
SMB_TECHNIQUE = "T1021.002"
_IPC_SHARE = re.compile(r"(?i)\\IPC\$")


def normalize_unc(path: str) -> str:
    """Collapse Zeek's escaped backslashes (``\\\\\\\\h\\\\s``) to UNC form (``\\\\h\\s``)."""
    stripped = path.lstrip("\\")
    leading = len(path) - len(stripped)
    body = re.sub(r"\\+", r"\\", stripped)
    return ("\\\\" if leading else "") + body


@dataclass
class _Candidate:
    signal: str
    orig: str
    resp: str
    ts: float
    last_ts: float
    confidence: float
    technique: str
    indicator: str
    evidence: dict[str, Any]
    uids: list[str] = field(default_factory=list)


class LateralMovementAnalyzer(BaseAnalyzer):
    name: ClassVar[str] = NAME
    required_logs: ClassVar[frozenset[str]] = frozenset({"conn"})
    DEFAULTS: ClassVar[Mapping[str, Any]] = {
        "window_seconds": 3600,
        "window_overlap": 0.0,
        "min_confidence": 0.6,
        "admin_ports": [445, 135, 3389, 5985, 5986, 22],
        "established_states": ["SF", "S1", "RSTO", "OTH"],
        "baseline_min_age_days": 7,
        "baseline_expiry_days": 30,
        "new_pair": {"base": 0.5, "non_admin_host_bonus": 0.2, "off_hours_bonus": 0.15},
        "admin_share": {
            "pattern": r"(?i)\\\\[^\\]+\\(ADMIN\$|C\$|[A-Z]\$)",
            "exec_extensions": [".exe", ".dll", ".ps1", ".bat", ".vbs", ".sct"],
            "write_actions": ["SMB::FILE_WRITE"],
            "open_actions": ["SMB::FILE_OPEN"],
            "exec_write_score": 0.9,
            "exec_open_score": 0.75,
            "other_write_score": 0.6,
            "max_files_in_evidence": 20,
        },
        "fanout": {
            "window_seconds": 600,
            "min_hosts": 10,
            "base": 0.4,
            "per_host": 0.02,
            "scan_states": ["S0", "REJ"],
            "scan_fraction": 0.8,
        },
        "correlation_seconds": 600,
        "merge_secondary_weight": 0.5,
    }

    def __init__(self) -> None:
        super().__init__()
        self._share_re: re.Pattern[str] | None = None
        self._baseline_age_days: float | None = None

    def validate_config(self, config: AnalyzerConfig) -> None:
        self._share_re = re.compile(str(config.section("admin_share")["pattern"]))

    @property
    def share_re(self) -> re.Pattern[str]:
        if self._share_re is None:
            self._share_re = re.compile(str(self.config.section("admin_share")["pattern"]))
        return self._share_re

    def status(self) -> dict[str, Any]:
        cfg = self.config
        min_age = cfg.float_param("baseline_min_age_days")
        age = self._baseline_age_days
        return {
            "baseline_age_days": None if age is None else round(age, 3),
            "baseline_min_age_days": min_age,
            "baseline_warmup": age is None or age < min_age,
            "baseline_entries": cfg.state.count() if cfg.state else 0,
        }

    # -- helpers ----------------------------------------------------------------

    def _excluded_source(self, ip: str) -> bool:
        nets = self.config.networks
        return nets.is_scanner_host(ip) or nets.lateral_allowed(ip) is not None

    def _admin_conns(self, window: LogWindow) -> list[Record]:
        cfg = self.config
        ports = {int(p) for p in cfg.param("admin_ports")}
        out = []
        for rec in window.records("conn"):
            orig, resp, port = rec.get("id.orig_h"), rec.get("id.resp_h"), rec.get("id.resp_p")
            if not (isinstance(orig, str) and isinstance(resp, str) and isinstance(port, int)):
                continue
            if port not in ports or orig == resp:
                continue
            if not (cfg.is_internal(orig) and cfg.is_internal(resp)):
                continue
            if self._excluded_source(orig):
                continue
            out.append(rec)
        return out

    # -- analysis ---------------------------------------------------------------

    def analyze(self, window: LogWindow) -> list[Detection]:
        conns = self._admin_conns(window)
        new_pairs = self._new_pairs(window, conns)
        candidates = list(new_pairs)
        candidates.extend(self._fanout(conns))
        min_conf = self.config.min_confidence
        return [self._to_detection(c) for c in candidates if c.confidence >= min_conf]

    def _new_pairs(self, window: LogWindow, conns: list[Record]) -> list[_Candidate]:
        cfg = self.config
        state = cfg.state
        if state is None:
            raise RuntimeError(f"{NAME} needs a StateStore for its first-seen baseline")
        established = set(cfg.param("established_states"))
        tuples: dict[tuple[str, str, int], list[Record]] = defaultdict(list)
        for rec in conns:
            if rec.get("conn_state") in established:
                tuples[(rec["id.orig_h"], rec["id.resp_h"], rec["id.resp_p"])].append(rec)

        all_ts = [float(r["ts"]) for r in window.records("conn")]
        if all_ts:
            state.ensure_baseline_started(min(all_ts))
        age_days = state.baseline_age(window.start) / DAY
        self._baseline_age_days = age_days
        mature = age_days >= cfg.float_param("baseline_min_age_days")

        new_by_pair: dict[tuple[str, str], list[tuple[int, list[Record]]]] = defaultdict(list)
        for (orig, resp, port), recs in tuples.items():
            key = f"{orig}|{resp}|{port}"
            if mature and not state.is_known(key):
                new_by_pair[(orig, resp)].append((port, recs))
            for rec in recs:
                state.observe(key, float(rec["ts"]))

        expiry = cfg.float_param("baseline_expiry_days") * DAY
        state.expire(window.start - expiry)

        candidates: list[_Candidate] = []
        for (orig, resp), port_groups in new_by_pair.items():
            for cluster in self._cluster_ports(port_groups):
                candidates.append(self._new_pair_candidate(orig, resp, cluster, age_days))
        return candidates

    def _cluster_ports(
        self, port_groups: list[tuple[int, list[Record]]]
    ) -> list[list[tuple[int, list[Record]]]]:
        """Group a pair's new ports whose activity lies within correlation_seconds."""
        gap_limit = self.config.float_param("correlation_seconds")
        ordered = sorted(port_groups, key=lambda pg: float(pg[1][0]["ts"]))
        clusters: list[list[tuple[int, list[Record]]]] = []
        cluster_end = -float("inf")
        for port, recs in ordered:
            first, last = float(recs[0]["ts"]), float(recs[-1]["ts"])
            if clusters and first - cluster_end <= gap_limit:
                clusters[-1].append((port, recs))
                cluster_end = max(cluster_end, last)
            else:
                clusters.append([(port, recs)])
                cluster_end = last
        return clusters

    def _new_pair_candidate(
        self, orig: str, resp: str, cluster: list[tuple[int, list[Record]]], age_days: float
    ) -> _Candidate:
        """One candidate per (orig, resp) cluster of newly seen admin ports."""
        cfg = self.config
        scoring = cfg.section("new_pair")
        priority = [int(p) for p in cfg.param("admin_ports")]
        ports = sorted((p for p, _ in cluster), key=priority.index)
        recs = sorted((r for _, rs in cluster for r in rs), key=lambda r: r["ts"])
        first, last = float(recs[0]["ts"]), float(recs[-1]["ts"])
        is_admin = cfg.networks.is_admin_host(orig)
        off_hours = not cfg.schedule.is_business_hours(first)
        parts = {
            "base": float(scoring["base"]),
            "non_admin_host_bonus": 0.0 if is_admin else float(scoring["non_admin_host_bonus"]),
            "off_hours_bonus": float(scoring["off_hours_bonus"]) if off_hours else 0.0,
        }
        primary = ports[0]
        return _Candidate(
            signal="new_admin_pair",
            orig=orig,
            resp=resp,
            ts=first,
            last_ts=last,
            confidence=min(sum(parts.values()), 1.0),
            technique=PORT_TECHNIQUES.get(primary, "T1021"),
            indicator=format_endpoint(resp, primary),
            evidence={
                "resp_ports": ports,
                "n_conns": len(recs),
                "conn_states": dict(Counter(str(r.get("conn_state")) for r in recs)),
                "services": sorted({str(r["service"]) for r in recs if r.get("service")}),
                "is_admin_host": is_admin,
                "off_hours": off_hours,
                "components": parts,
                "baseline_age_days": age_days,
            },
            uids=[r["uid"] for r in recs if r.get("uid")],
        )

    def _admin_share(self, window: LogWindow) -> list[_Candidate]:
        cfg = self.config
        settings = cfg.section("admin_share")
        exts = tuple(e.lower() for e in settings["exec_extensions"])
        write_actions = set(settings["write_actions"])
        open_actions = set(settings["open_actions"])

        files: dict[tuple[str, str, str, str], list[Record]] = defaultdict(list)
        ipc: Counter[tuple[str, str]] = Counter()
        for rec in window.records("smb_files"):
            orig, resp = rec.get("id.orig_h"), rec.get("id.resp_h")
            raw_path = rec.get("path")
            if not (isinstance(orig, str) and isinstance(resp, str) and isinstance(raw_path, str)):
                continue
            if not (cfg.is_internal(orig) and cfg.is_internal(resp)) or self._excluded_source(orig):
                continue
            path = normalize_unc(raw_path)
            if _IPC_SHARE.search(path):
                ipc[(orig, resp)] += 1
                continue
            if not self.share_re.search(path):
                continue
            name = rec.get("name") if isinstance(rec.get("name"), str) else ""
            files[(orig, resp, path, str(name))].append(rec)

        per_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        pair_records: dict[tuple[str, str], list[Record]] = defaultdict(list)
        for (orig, resp, path, name), recs in files.items():
            actions = {str(r.get("action")) for r in recs}
            is_exec = name.lower().endswith(exts)
            wrote = bool(actions & write_actions)
            opened = bool(actions & open_actions)
            if is_exec and wrote:
                score, reason = float(settings["exec_write_score"]), "executable_write"
            elif is_exec and opened:
                score, reason = float(settings["exec_open_score"]), "executable_open"
            elif wrote:
                score, reason = float(settings["other_write_score"]), "file_write"
            else:
                continue
            sizes = [r["size"] for r in recs if isinstance(r.get("size"), int)]
            per_pair[(orig, resp)].append(
                {
                    "path": path,
                    "name": name,
                    "actions": sorted(actions),
                    "size": max(sizes) if sizes else None,
                    "score": score,
                    "reason": reason,
                    "first_ts": float(recs[0]["ts"]),
                }
            )
            pair_records[(orig, resp)].extend(recs)

        candidates = []
        limit = int(settings["max_files_in_evidence"])
        for (orig, resp), entries in per_pair.items():
            entries.sort(key=lambda e: (-e["score"], e["first_ts"], e["name"]))
            top = entries[0]
            recs = sorted(pair_records[(orig, resp)], key=lambda r: r["ts"])
            candidates.append(
                _Candidate(
                    signal="admin_share_write",
                    orig=orig,
                    resp=resp,
                    ts=float(recs[0]["ts"]),
                    last_ts=float(recs[-1]["ts"]),
                    confidence=top["score"],
                    technique=SMB_TECHNIQUE,
                    indicator=f"{top['path']}\\{top['name']}" if top["name"] else top["path"],
                    evidence={
                        "files": entries[:limit],
                        "n_files": len(entries),
                        "ipc_access_count": ipc.get((orig, resp), 0),
                        "secondary_techniques": [{"technique_id": "T1570", "tactic": TACTIC}]
                        if top["reason"].startswith("executable")
                        else [],
                    },
                    uids=[r["uid"] for r in recs if r.get("uid")],
                )
            )
        return candidates

    def _merge(self, new_pairs: list[_Candidate], shares: list[_Candidate]) -> list[_Candidate]:
        cfg = self.config
        gap_limit = cfg.float_param("correlation_seconds")
        weight = cfg.float_param("merge_secondary_weight")
        merged: list[_Candidate] = []
        used_shares: set[int] = set()
        for pair in new_pairs:
            match_index = None
            for i, share in enumerate(shares):
                if i in used_shares or (share.orig, share.resp) != (pair.orig, pair.resp):
                    continue
                gap = max(share.ts - pair.last_ts, pair.ts - share.last_ts, 0.0)
                if gap <= gap_limit:
                    match_index = i
                    break
            if match_index is None:
                merged.append(pair)
                continue
            used_shares.add(match_index)
            share = shares[match_index]
            merged.append(
                _Candidate(
                    signal="new_admin_pair+admin_share_write",
                    orig=pair.orig,
                    resp=pair.resp,
                    ts=min(pair.ts, share.ts),
                    last_ts=max(pair.last_ts, share.last_ts),
                    confidence=min(pair.confidence + weight * share.confidence, 1.0),
                    technique=SMB_TECHNIQUE,
                    indicator=share.indicator,
                    evidence={
                        "new_admin_pair": {**pair.evidence, "confidence": pair.confidence},
                        "admin_share_write": {**share.evidence, "confidence": share.confidence},
                        "merge": {
                            "rule": "min(c1 + w*c2, 1.0)",
                            "c1": pair.confidence,
                            "c2": share.confidence,
                            "w": weight,
                        },
                    },
                    uids=pair.uids + share.uids,
                )
            )
        merged.extend(s for i, s in enumerate(shares) if i not in used_shares)
        return merged

    def _fanout(self, conns: list[Record]) -> list[_Candidate]:
        cfg = self.config
        settings = cfg.section("fanout")
        span = float(settings["window_seconds"])
        min_hosts = int(settings["min_hosts"])
        scan_states = set(settings["scan_states"])
        per_src: dict[str, list[Record]] = defaultdict(list)
        for rec in conns:
            per_src[rec["id.orig_h"]].append(rec)

        candidates = []
        for orig, recs in per_src.items():
            recs.sort(key=lambda r: r["ts"])
            counts: Counter[str] = Counter()
            best = (0, 0, -1)
            lo = 0
            for hi, rec in enumerate(recs):
                counts[rec["id.resp_h"]] += 1
                while float(rec["ts"]) - float(recs[lo]["ts"]) > span:
                    old = recs[lo]["id.resp_h"]
                    counts[old] -= 1
                    if counts[old] == 0:
                        del counts[old]
                    lo += 1
                if len(counts) > best[0]:
                    best = (len(counts), lo, hi)
            n_hosts, lo, hi = best
            if n_hosts < min_hosts:
                continue
            burst = recs[lo : hi + 1]
            failed = sum(1 for r in burst if r.get("conn_state") in scan_states)
            fraction = failed / len(burst)
            pattern = "scan" if fraction > float(settings["scan_fraction"]) else "access"
            ports = Counter(int(r["id.resp_p"]) for r in burst)
            dominant = ports.most_common(1)[0][0]
            confidence = min(
                float(settings["base"]) + (n_hosts - min_hosts) * float(settings["per_host"]), 1.0
            )
            candidates.append(
                _Candidate(
                    signal=f"fanout_{pattern}",
                    orig=orig,
                    resp="",
                    ts=float(burst[0]["ts"]),
                    last_ts=float(burst[-1]["ts"]),
                    confidence=confidence,
                    technique=SCAN_TECHNIQUE
                    if pattern == "scan"
                    else PORT_TECHNIQUES.get(dominant, "T1021"),
                    indicator=orig,
                    evidence={
                        "pattern": pattern,
                        "n_hosts": n_hosts,
                        "n_conns": len(burst),
                        "failed_fraction": fraction,
                        "ports": {str(p): c for p, c in sorted(ports.items())},
                        "targets": sorted({r["id.resp_h"] for r in burst})[:50],
                        "fanout_window_seconds": span,
                    },
                    uids=[r["uid"] for r in burst if r.get("uid")],
                )
            )
        return candidates

    def _to_detection(self, cand: _Candidate) -> Detection:
        is_scan = cand.technique == SCAN_TECHNIQUE
        severity = severity_for(round(cand.confidence, 4))
        evidence = {"signal": cand.signal, **cand.evidence}
        if is_scan:
            severity = reduce_severity(severity)
            evidence["severity_adjustment"] = "scan pattern: reduced one band (Discovery)"
        return Detection.build(
            ts=cand.ts,
            last_ts=cand.last_ts,
            detector=NAME,
            src=cand.orig,
            dst=cand.resp or None,
            indicator=cand.indicator,
            confidence=cand.confidence,
            technique_id=cand.technique,
            tactic=SCAN_TACTIC if is_scan else TACTIC,
            evidence=evidence,
            uids=cand.uids,
            severity=severity,
        )

    # -- export -----------------------------------------------------------------

    def _excluded_source_cidrs(self) -> list[str]:
        nets = self.config.networks
        return nets.scanner_hosts.as_strings() + [
            str(e.network) for e in nets.lateral_allow_sources
        ]

    def _fanout_hosts_needed(self) -> int:
        """Smallest distinct-host count whose fan-out score reaches min_confidence."""
        settings = self.config.section("fanout")
        min_hosts = int(settings["min_hosts"])
        base, per_host = float(settings["base"]), float(settings["per_host"])
        target = self.config.min_confidence
        n = min_hosts
        while base + (n - min_hosts) * per_host < target - 1e-9 and n < 100_000:
            n += 1
        return n

    def _admin_share_sigma_regex(self) -> str:
        # Equivalent to the Python pattern after normalize_unc(): tolerate the
        # doubled backslashes some Zeek pipelines emit.
        return r"(?i)\\{2,}[^\\]+\\+(ADMIN\$|C\$|[A-Z]\$)"

    def to_sigma(self) -> list[SigmaRule]:
        from zdp import __release_date__

        cfg = self.config
        h = cfg.config_hash
        settings = cfg.section("admin_share")
        min_conf = cfg.min_confidence
        internal = cfg.networks.internal.as_strings()
        excluded = self._excluded_source_cidrs()

        branches: list[str] = []
        detection: dict[str, Any] = {
            "selection_share": {"path|re": self._admin_share_sigma_regex()},
            "selection_internal": {"id.orig_h|cidr": internal, "id.resp_h|cidr": internal},
        }
        exts = list(settings["exec_extensions"])
        if (
            float(settings["exec_write_score"]) >= min_conf
            or float(settings["exec_open_score"]) >= min_conf
        ):
            actions = []
            if float(settings["exec_write_score"]) >= min_conf:
                actions += list(settings["write_actions"])
            if float(settings["exec_open_score"]) >= min_conf:
                actions += list(settings["open_actions"])
            detection["selection_exec"] = {"action": sorted(set(actions)), "name|endswith": exts}
            branches.append("selection_exec")
        if float(settings["other_write_score"]) >= min_conf:
            detection["selection_write"] = {"action": list(settings["write_actions"])}
            branches.append("selection_write")
        if excluded:
            detection["filter_allowlisted_sources"] = {"id.orig_h|cidr": excluded}
        if not branches:
            return []
        condition = f"selection_share and selection_internal and ({' or '.join(branches)})"
        if excluded:
            condition += " and not filter_allowlisted_sources"
        detection["condition"] = condition
        share_rule = {
            "title": "ZDP lateral movement - write or executable on Windows admin share",
            "id": rule_uuid(NAME, "admin_share_write", h),
            "status": "experimental",
            "description": (
                "Internal host writing to, or opening an executable/script on, an ADMIN$, C$ or "
                "drive-letter share of another internal host (PsExec-style tool staging). "
                "Equivalent to signal 2 of zdp's lateral_movement analyzer at "
                f"min_confidence {min_conf}."
            ),
            "author": "zeek-detection-pack (generated)",
            "date": __release_date__,
            "tags": [
                "attack.lateral-movement",
                "attack.t1021.002",
                "attack.t1570",
            ],
            "logsource": {"product": "zeek", "service": "smb_files"},
            "detection": detection,
            "fields": ["id.orig_h", "id.resp_h", "path", "name", "action", "size"],
            "falsepositives": [
                "Software deployment (SCCM/Intune), backup and AV servers - allowlist them in "
                "networks.yaml lateral_allow_sources with a justification",
            ],
            "level": "high",
        }

        ports = [int(p) for p in cfg.param("admin_ports")]
        base_name = f"zdp_{NAME}_admin_port_conn"
        base_detection: dict[str, Any] = {
            "selection": {
                "id.resp_p": ports,
                "id.orig_h|cidr": internal,
                "id.resp_h|cidr": internal,
            }
        }
        if excluded:
            base_detection["filter_allowlisted_sources"] = {"id.orig_h|cidr": excluded}
            base_detection["condition"] = "selection and not filter_allowlisted_sources"
        else:
            base_detection["condition"] = "selection"
        fanout = cfg.section("fanout")
        minutes = max(1, round(float(fanout["window_seconds"]) / 60))
        hosts = self._fanout_hosts_needed()
        base = {
            "title": "ZDP lateral movement - internal admin-port connection (base event)",
            "id": rule_uuid(NAME, "admin_port_conn", h),
            "name": base_name,
            "status": "experimental",
            "description": "Base event for the zdp admin-port fan-out correlation.",
            "author": "zeek-detection-pack (generated)",
            "date": __release_date__,
            "tags": ["attack.lateral-movement", "attack.t1021"],
            "logsource": {"product": "zeek", "service": "conn"},
            "detection": base_detection,
            "level": "informational",
        }
        correlation = {
            "title": "ZDP lateral movement - admin-port fan-out from one host",
            "id": rule_uuid(NAME, "fanout", h),
            "status": "experimental",
            "description": (
                f"One internal host contacting at least {hosts} distinct internal hosts on admin "
                f"ports within {minutes}m - the host count at which zdp's fan-out score reaches "
                "min_confidence. Approximate: does not separate scan from access patterns."
            ),
            "author": "zeek-detection-pack (generated)",
            "date": __release_date__,
            "tags": [
                "attack.lateral-movement",
                "attack.t1021",
                "attack.discovery",
                "attack.t1046",
            ],
            "correlation": {
                "type": "value_count",
                "rules": [base_name],
                "group-by": ["id.orig_h"],
                "timespan": f"{minutes}m",
                "condition": {"gte": hosts, "field": "id.resp_h"},
            },
            "falsepositives": [
                "Vulnerability scanners and inventory tools (allowlist as scanner_hosts)"
            ],
            "level": "medium",
        }
        return [
            SigmaRule(
                detector=NAME, signal="admin_share_write", tier=TIER_FULL, document=share_rule
            ),
            SigmaRule(
                detector=NAME,
                signal="fanout",
                tier=TIER_APPROX,
                document=correlation,
                companions=(base,),
            ),
        ]

    def to_suricata(self) -> list[SuricataRule]:
        cfg = self.config
        h = cfg.config_hash
        settings = cfg.section("admin_share")
        excluded = self._excluded_source_cidrs()
        src = (
            "$HOME_NET"
            if not excluded
            else "[$HOME_NET," + ",".join(f"!{c}" for c in excluded) + "]"
        )
        exts = "|".join(re.escape(e.lstrip(".")) for e in settings["exec_extensions"])
        flowbit = "zdp.lateral.admin_share"
        rules: list[SuricataRule] = []

        def add(
            signal: str, tier: str, body: str, technique: str, tactic_id: str, note: str
        ) -> None:
            sid = suricata_sid(NAME, signal, h)
            text = (
                f"{body} metadata:zdp_detector {NAME}, zdp_signal {signal}, zdp_tier {tier}, "
                f"zdp_rule_id {rule_uuid(NAME, signal, h)}, zdp_config_hash {h}, "
                f"mitre_technique_id {technique}, mitre_tactic_id {tactic_id}; sid:{sid}; rev:1;)"
            )
            rules.append(SuricataRule(NAME, signal, tier, sid, text, (note,)))

        add(
            "admin_share_connect",
            TIER_APPROX,
            f"alert smb {src} any -> $HOME_NET any "
            '(msg:"ZDP lateral_movement admin share tree connect (flowbit setter)"; '
            'flow:to_server,established; smb.share; pcre:"/\\x5c(ADMIN|[A-Z])\\x24$/i"; '
            f"flowbits:set,{flowbit}; flowbits:noalert; classtype:policy-violation;",
            SMB_TECHNIQUE,
            "TA0008",
            "Marks SMB flows that connected to ADMIN$/C$/drive shares; does not alert.",
        )
        add(
            "admin_share_exec_transfer",
            TIER_APPROX,
            f"alert smb {src} any -> $HOME_NET any "
            '(msg:"ZDP lateral_movement [approx] executable/script transferred over SMB after '
            'admin share connect"; flow:to_server,established; '
            f'flowbits:isset,{flowbit}; file.name; pcre:"/\\.({exts})$/i"; '
            "classtype:trojan-activity;",
            SMB_TECHNIQUE,
            "TA0008",
            "Same-flow heuristic; Suricata cannot bind a file to the tree it was written to.",
        )
        ports = ",".join(str(int(p)) for p in cfg.param("admin_ports"))
        fanout = cfg.section("fanout")
        seconds = int(float(fanout["window_seconds"]))
        hosts = self._fanout_hosts_needed()
        add(
            "fanout",
            TIER_APPROX,
            f"alert tcp {src} any -> $HOME_NET [{ports}] "
            f'(msg:"ZDP lateral_movement [approx] >= {hosts} admin-port session attempts from '
            f'one host within {seconds}s"; flow:to_server,not_established; flags:S,CE; '
            f"threshold:type both, track by_src, count {hosts}, seconds {seconds}; "
            "classtype:network-scan;",
            "T1021",
            "TA0008",
            "Counts SYNs, not distinct targets; cannot separate scan from access.",
        )
        return rules

    def export_skips(self) -> list[ExportSkip]:
        reason = (
            "Requires a persistent first-seen baseline of (orig, resp, port) tuples with a "
            "7-day warm-up; neither Sigma nor Suricata can express stateful baselines."
        )
        return [
            ExportSkip(NAME, "new_admin_pair", "sigma", reason),
            ExportSkip(NAME, "new_admin_pair", "suricata", reason),
        ]


def analyze(
    log_dir: str | Path, config: Config | None = None, state: StateStore | None = None
) -> list[Detection]:
    """Run the lateral movement detector over a Zeek log directory."""
    return LateralMovementAnalyzer.run_on_directory(log_dir, config=config, state=state)
