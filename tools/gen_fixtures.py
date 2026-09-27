#!/usr/bin/env python3
"""Deterministic generator for the labeled fixtures under ``fixtures/``.

Every scenario is synthesized from a fixed seed, so re-running this tool
reproduces the committed files byte-for-byte (CI enforces this with
``git diff --exit-code fixtures``). No production data is involved.

Logs mirror Zeek 9 (LTS) output: TSV files carry the full ``#separator`` …
``#close`` header block with Zeek's field order and types, and JSON files use
Zeek's flat dotted keys with unset fields omitted. Each scenario mixes the
two formats so both reader paths are exercised.

Address plan (documentation / private ranges only):

* internal clients ``10.1.2.0/24``–``10.1.4.0/24``, servers ``10.1.0.0/24``,
  ``10.1.5.0/24``, ``10.1.6.0/24``, infrastructure ``10.1.8.0/24``–``10.1.9.0/24``,
  IPv6 clients ``fd00:10:1:2::/64``;
* external benign web ``198.51.100.0/24`` (TEST-NET-2), ``2001:db8:100::/48``;
* external "attacker" infrastructure ``203.0.113.0/24`` (TEST-NET-3),
  ``2001:db8:40::/48``; vendor/NTP endpoints ``192.0.2.0/24`` (TEST-NET-1).

Usage::

    python tools/gen_fixtures.py            # regenerate all scenarios
    python tools/gen_fixtures.py --check    # exit 1 if committed files differ
"""

from __future__ import annotations

import argparse
import base64
import filecmp
import json
import math
import random
import shutil
import string
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"
HOUR = 3600.0
DAY = 86_400.0

RESOLVER = "10.1.0.53"
DC = "10.1.0.10"
FILE_SERVER = "10.1.5.10"
APP_SERVER = "10.1.5.20"
ADMIN_WS = "10.1.8.5"
SCCM = "10.1.9.10"
BACKUP = "10.1.9.20"
SCANNER = "10.1.9.50"
MAIL = "10.1.0.25"

# --- Zeek 9 schemas (field, type) -------------------------------------------

SCHEMAS: dict[str, list[tuple[str, str]]] = {
    "conn": [
        ("ts", "time"),
        ("uid", "string"),
        ("id.orig_h", "addr"),
        ("id.orig_p", "port"),
        ("id.resp_h", "addr"),
        ("id.resp_p", "port"),
        ("proto", "enum"),
        ("service", "string"),
        ("duration", "interval"),
        ("orig_bytes", "count"),
        ("resp_bytes", "count"),
        ("conn_state", "string"),
        ("local_orig", "bool"),
        ("local_resp", "bool"),
        ("missed_bytes", "count"),
        ("history", "string"),
        ("orig_pkts", "count"),
        ("orig_ip_bytes", "count"),
        ("resp_pkts", "count"),
        ("resp_ip_bytes", "count"),
        ("tunnel_parents", "set[string]"),
        ("ip_proto", "count"),
    ],
    "dns": [
        ("ts", "time"),
        ("uid", "string"),
        ("id.orig_h", "addr"),
        ("id.orig_p", "port"),
        ("id.resp_h", "addr"),
        ("id.resp_p", "port"),
        ("proto", "enum"),
        ("trans_id", "count"),
        ("rtt", "interval"),
        ("query", "string"),
        ("qclass", "count"),
        ("qclass_name", "string"),
        ("qtype", "count"),
        ("qtype_name", "string"),
        ("rcode", "count"),
        ("rcode_name", "string"),
        ("AA", "bool"),
        ("TC", "bool"),
        ("RD", "bool"),
        ("RA", "bool"),
        ("Z", "count"),
        ("answers", "vector[string]"),
        ("TTLs", "vector[interval]"),
        ("rejected", "bool"),
        ("opcode", "count"),
        ("opcode_name", "string"),
    ],
    "smb_files": [
        ("ts", "time"),
        ("uid", "string"),
        ("id.orig_h", "addr"),
        ("id.orig_p", "port"),
        ("id.resp_h", "addr"),
        ("id.resp_p", "port"),
        ("fuid", "string"),
        ("action", "enum"),
        ("path", "string"),
        ("name", "string"),
        ("size", "count"),
        ("prev_name", "string"),
        ("times.modified", "time"),
        ("times.accessed", "time"),
        ("times.created", "time"),
        ("times.changed", "time"),
    ],
}

QTYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "NULL": 10,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "HTTPS": 65,
}
RCODES = {"NOERROR": 0, "SERVFAIL": 2, "NXDOMAIN": 3}
IP_PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
HISTORY = {"SF": "ShADadFf", "S0": "S", "REJ": "Sr", "RSTO": "ShADR", "S1": "ShAD", "OTH": "Da"}

#: Benign web destinations: (ip, port, service, hostname). Hostnames resolve
#: under Tranco-allowlisted registered domains.
WEB_DSTS: list[tuple[str, int, str, str]] = [
    (f"198.51.100.{10 + i}", 443, "ssl", host)
    for i, host in enumerate(
        [
            "www.google.com",
            "outlook.office365.com",
            "login.microsoftonline.com",
            "www.wikipedia.org",
            "github.com",
            "www.bbc.co.uk",
            "teams.microsoft.com",
            "www.linkedin.com",
            "slack.com",
            "zoom.us",
            "www.salesforce.com",
            "www.dropbox.com",
            "docs.google.com",
            "www.apple.com",
            "www.amazon.com",
            "news.ycombinator.com",
            "www.reddit.com",
            "stackoverflow.com",
            "www.nytimes.com",
            "www.cloudflare.com",
        ]
    )
] + [
    (f"198.51.100.{40 + i}", 80, "http", h)
    for i, h in enumerate(["www.example.com", "intranet-cdn.example.com", "www.bing.com"])
]
WEB_DSTS_V6 = [
    ("2001:db8:100::10", 443, "ssl", "www.google.com"),
    ("2001:db8:100::11", 443, "ssl", "github.com"),
]


# --- record writers -------------------------------------------------------------


def _escape(value: str) -> str:
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\t" or not ch.isprintable():
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _tsv_value(value: Any, ztype: str) -> str:
    if value is None:
        return "-"
    if ztype.startswith(("set[", "vector[")):
        if not value:
            return "(empty)"
        inner = ztype[ztype.index("[") + 1 : -1]
        return ",".join(_tsv_value(v, inner) for v in value)
    if ztype in ("time", "interval", "double"):
        return f"{float(value):.6f}"
    if ztype == "bool":
        return "T" if value else "F"
    if ztype in ("count", "int", "port"):
        return str(int(value))
    text = str(value)
    return "(empty)" if text == "" else _escape(text)


def write_tsv(path: Path, log_type: str, records: Sequence[dict[str, Any]]) -> None:
    schema = SCHEMAS[log_type]
    first = records[0]["ts"] if records else 0.0
    last = records[-1]["ts"] if records else 0.0
    stamp = lambda ts: time.strftime("%Y-%m-%d-%H-%M-%S", time.gmtime(ts))  # noqa: E731
    lines = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        f"#path\t{log_type}",
        f"#open\t{stamp(first)}",
        "#fields\t" + "\t".join(f for f, _ in schema),
        "#types\t" + "\t".join(t for _, t in schema),
    ]
    lines += ["\t".join(_tsv_value(r.get(f), t) for f, t in schema) for r in records]
    lines.append(f"#close\t{stamp(last + 1)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json(path: Path, log_type: str, records: Sequence[dict[str, Any]]) -> None:
    schema = SCHEMAS[log_type]
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            obj = {f: rec[f] for f, _ in schema if rec.get(f) is not None}
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")


# --- scenario builder -----------------------------------------------------------


@dataclass
class Scenario:
    name: str
    seed: int
    start: float
    description: str
    formats: dict[str, str]
    rng: random.Random = field(init=False)
    records: dict[str, list[dict[str, Any]]] = field(init=False)
    labels: list[dict[str, Any]] = field(default_factory=list)
    benign: list[dict[str, Any]] = field(default_factory=list)
    readme: list[str] = field(default_factory=list)
    site: dict[str, Any] | None = None
    baseline: dict[str, list[float]] | None = None
    baseline_started: float | None = None

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)
        self.records = {"conn": [], "dns": [], "smb_files": []}

    # identifiers
    def uid(self, prefix: str = "C") -> str:
        alphabet = string.ascii_letters + string.digits
        return prefix + "".join(self.rng.choice(alphabet) for _ in range(17))

    def eport(self) -> int:
        return self.rng.randrange(49152, 65535)

    # records
    def conn(
        self,
        ts: float,
        orig: str,
        resp: str,
        rport: int,
        proto: str = "tcp",
        *,
        service: str | None = None,
        duration: float | None = None,
        orig_bytes: int = 0,
        resp_bytes: int = 0,
        state: str = "SF",
        oport: int | None = None,
        uid: str | None = None,
    ) -> str:
        uid = uid or self.uid()
        overhead = 28 if proto == "udp" else 40
        if state in ("S0", "REJ"):
            orig_pkts, resp_pkts = (1, 1 if state == "REJ" else 0)
            orig_bytes = resp_bytes = 0
        else:
            orig_pkts = max(1, math.ceil(orig_bytes / 1400)) + (0 if proto == "udp" else 3)
            resp_pkts = max(1, math.ceil(resp_bytes / 1400)) + (0 if proto == "udp" else 2)
        history = "Dd" if proto == "udp" and state == "SF" else HISTORY[state]
        self.records["conn"].append(
            {
                "ts": round(ts, 6),
                "uid": uid,
                "id.orig_h": orig,
                "id.orig_p": oport or self.eport(),
                "id.resp_h": resp,
                "id.resp_p": rport,
                "proto": proto,
                "service": service,
                "duration": None if duration is None else round(duration, 6),
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "conn_state": state,
                "local_orig": _is_local(orig),
                "local_resp": _is_local(resp),
                "missed_bytes": 0,
                "history": history,
                "orig_pkts": orig_pkts,
                "orig_ip_bytes": orig_bytes + orig_pkts * overhead,
                "resp_pkts": resp_pkts,
                "resp_ip_bytes": resp_bytes + resp_pkts * overhead,
                "tunnel_parents": None,
                "ip_proto": IP_PROTO[proto],
            }
        )
        return uid

    def dns(
        self,
        ts: float,
        orig: str,
        query: str,
        qtype: str = "A",
        rcode: str = "NOERROR",
        *,
        answers: list[str] | None = None,
        ttl: float = 300.0,
        resolver: str = RESOLVER,
    ) -> str:
        oport = self.eport()
        rtt = round(self.rng.uniform(0.0008, 0.04), 6)
        qlen = len(query) + 18
        answers = answers or []
        uid = self.conn(
            ts,
            orig,
            resolver,
            53,
            "udp",
            service="dns",
            duration=rtt,
            orig_bytes=qlen,
            resp_bytes=qlen + sum(len(a) + 12 for a in answers),
            oport=oport,
        )
        self.records["dns"].append(
            {
                "ts": round(ts, 6),
                "uid": uid,
                "id.orig_h": orig,
                "id.orig_p": oport,
                "id.resp_h": resolver,
                "id.resp_p": 53,
                "proto": "udp",
                "trans_id": self.rng.randrange(1, 65535),
                "rtt": rtt,
                "query": query,
                "qclass": 1,
                "qclass_name": "C_INTERNET",
                "qtype": QTYPES[qtype],
                "qtype_name": qtype,
                "rcode": RCODES[rcode],
                "rcode_name": rcode,
                "AA": False,
                "TC": False,
                "RD": True,
                "RA": True,
                "Z": 0,
                "answers": answers or None,
                "TTLs": [ttl] * len(answers) if answers else None,
                "rejected": False,
                "opcode": 0,
                "opcode_name": "query",
            }
        )
        return uid

    def smb_file(
        self,
        ts: float,
        conn_uid: str,
        orig: str,
        oport: int,
        resp: str,
        action: str,
        share_path: str,
        name: str,
        size: int,
    ) -> None:
        mtime = round(ts - self.rng.uniform(DAY, 90 * DAY), 6)
        self.records["smb_files"].append(
            {
                "ts": round(ts, 6),
                "uid": conn_uid,
                "id.orig_h": orig,
                "id.orig_p": oport,
                "id.resp_h": resp,
                "id.resp_p": 445,
                "fuid": None if action == "SMB::FILE_OPEN" else self.uid("F"),
                "action": action,
                "path": share_path,
                "name": name,
                "size": size,
                "prev_name": None,
                "times.modified": mtime,
                "times.accessed": mtime,
                "times.created": mtime,
                "times.changed": mtime,
            }
        )

    def smb_session(
        self,
        ts: float,
        orig: str,
        resp: str,
        share: str,
        files: Iterable[tuple[str, str, int]],
        *,
        duration: float = 30.0,
        observe: bool = True,
    ) -> str:
        """An SMB conn plus smb_files rows; ``files`` = (action, name, size)."""
        oport = self.eport()
        uid = self.conn(
            ts,
            orig,
            resp,
            445,
            service="smb",
            duration=duration,
            orig_bytes=self.rng.randrange(2_000, 60_000),
            resp_bytes=self.rng.randrange(2_000, 200_000),
            oport=oport,
        )
        for i, (action, name, size) in enumerate(files):
            self.smb_file(ts + 0.05 + 0.01 * i, uid, orig, oport, resp, action, share, name, size)
        if observe:
            self.observe(orig, resp, 445, ts)
        return uid

    def observe(self, orig: str, resp: str, port: int, ts: float) -> None:
        if self.baseline is not None:
            key = f"{orig}|{resp}|{port}"
            seen = self.baseline.setdefault(key, [ts, ts])
            seen[0], seen[1] = min(seen[0], ts), max(seen[1], ts)

    def label(self, **kwargs: Any) -> None:
        self.labels.append(kwargs)

    def note_benign(self, description: str, **kwargs: Any) -> None:
        self.benign.append({"description": description, **kwargs})

    # output
    def write(self, root: Path) -> None:
        out = root / self.name
        out.mkdir(parents=True, exist_ok=True)
        for log_type, records in self.records.items():
            if not records:
                continue
            records.sort(key=lambda r: (r["ts"], r["uid"]))
            fmt = self.formats.get(log_type, "tsv")
            writer = write_tsv if fmt == "tsv" else write_json
            writer(out / f"{log_type}.log", log_type, records)
        labels = {
            "schema_version": 1,
            "scenario": self.name,
            "description": self.description,
            "labels": self.labels,
            "benign": self.benign,
        }
        (out / "labels.json").write_text(json.dumps(labels, indent=2) + "\n", encoding="utf-8")
        if self.site is not None:
            (out / "site.yaml").write_text(_yaml(self.site), encoding="utf-8")
        if self.baseline is not None and self.baseline_started is not None:
            # Baseline entries are the tuples observed during the (synthetic)
            # weeks before the fixture, i.e. everything benign in it.
            seed = {
                "schema_version": 1,
                "analyzers": {
                    "lateral_movement": {
                        "meta": {"baseline_started": repr(self.baseline_started)},
                        "seen": [
                            {
                                "key": k,
                                "first_seen": self.baseline_started + DAY,
                                "last_seen": self.start - HOUR,
                            }
                            for k in sorted(self.baseline)
                        ],
                    }
                },
            }
            (out / "state_seed.json").write_text(
                json.dumps(seed, indent=2) + "\n", encoding="utf-8"
            )
        counts = ", ".join(
            f"{k}: {len(v)} records ({self.formats.get(k, 'tsv').upper()})"
            for k, v in self.records.items()
            if v
        )
        readme = [
            f"# Fixture: `{self.name}`",
            "",
            self.description,
            "",
            "## Provenance",
            "",
            f"Synthetic. Generated by `tools/gen_fixtures.py` with seed `{self.seed}`; "
            "re-running the tool reproduces these files byte-for-byte. No production data. "
            "Addresses are RFC 1918 / RFC 4193 (internal) and RFC 5737 / RFC 3849 "
            "documentation ranges (external).",
            "",
            f"Start: `{self.start:.0f}` ({_iso(self.start)}). Logs: {counts}.",
            "",
            "## Contents",
            "",
            *self.readme,
            "",
            "## Ground truth",
            "",
            f"`labels.json` lists {len(self.labels)} positive event(s)"
            + (
                " — this is a pure-negative scenario: any detection is a false positive."
                if not self.labels
                else "."
            )
            + f" The `benign` section documents {len(self.benign)} deliberately included "
            "look-alike behaviour(s) that must NOT be detected.",
        ]
        if self.site is not None:
            readme += [
                "",
                "`site.yaml` is a site-inventory overlay (scanner hosts, allowlisted "
                "deployment servers, internal zones). Thresholds stay at defaults.",
            ]
        if self.baseline is not None:
            readme += [
                "",
                "`state_seed.json` seeds the lateral-movement first-seen baseline "
                "(started 14 days before the fixture) with every benign admin-service "
                "tuple, so the new-pair signal is active rather than in warm-up.",
            ]
        (out / "README.md").write_text("\n".join(readme) + "\n", encoding="utf-8")


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _is_local(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "fd00:")) or (
        ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31
    )


def _yaml(data: Any, indent: int = 0) -> str:
    """Tiny deterministic YAML emitter for the site overlays (no PyYAML needed)."""
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)) and value:
                lines.append(f"{pad}{key}:")
                lines.append(_yaml(value, indent + 1).rstrip("\n"))
            else:
                lines.append(f"{pad}{key}: {_scalar(value)}")
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                first, *rest = list(item.items())
                lines.append(f"{pad}- {first[0]}: {_scalar(first[1])}")
                lines += [f"{pad}  {k}: {_scalar(v)}" for k, v in rest]
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    return "\n".join(lines) + "\n"


def _scalar(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return "{}" if isinstance(value, dict) else "[]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


# --- background traffic ---------------------------------------------------------


def lognormal_int(rng: random.Random, mu: float, sigma: float, lo: int = 1) -> int:
    return max(lo, int(rng.lognormvariate(mu, sigma)))


def web_background(
    sc: Scenario,
    hosts: Sequence[str],
    start: float,
    end: float,
    *,
    busy_gap: float = 240.0,
    quiet_gap: float = 1800.0,
    dns_share: float = 0.3,
) -> None:
    rng = sc.rng
    for host in hosts:
        dsts = WEB_DSTS_V6 if ":" in host else WEB_DSTS
        t = start + rng.uniform(0, 300)
        while t < end:
            ip, port, service, name = rng.choice(dsts)
            if rng.random() < dns_share:
                qtype = "AAAA" if ":" in ip else "A"
                sc.dns(t - rng.uniform(0.01, 0.2), host, name, qtype, answers=[ip])
            sc.conn(
                t,
                host,
                ip,
                port,
                service=service,
                duration=round(rng.lognormvariate(0.5, 1.2), 6),
                orig_bytes=lognormal_int(rng, 6.8, 0.9),
                resp_bytes=lognormal_int(rng, 9.5, 1.6),
            )
            hour = time.gmtime(t).tm_hour
            gap = busy_gap if 8 <= hour < 18 else quiet_gap
            t += rng.expovariate(1.0 / gap)


def dns_background(
    sc: Scenario, hosts: Sequence[str], start: float, end: float, gap: float
) -> None:
    rng = sc.rng
    names = [d[3] for d in WEB_DSTS] + [
        "time.windows.com",
        "settings-win.data.microsoft.com",
        "www.msftconnecttest.com",
        "ocsp.digicert.com",
        "update.googleapis.com",
        "clients4.google.com",
    ]
    for host in hosts:
        t = start + rng.uniform(0, gap)
        while t < end:
            name = rng.choice(names)
            qtype = rng.choice(["A", "A", "A", "AAAA", "HTTPS"])
            answers = [f"198.51.100.{rng.randrange(10, 60)}"] if qtype == "A" else []
            sc.dns(t, host, name, qtype, answers=answers)
            t += rng.expovariate(1.0 / gap)


def office_smb_and_dc(sc: Scenario, hosts: Sequence[str], start: float, end: float) -> None:
    """File-server SMB sessions and DC traffic; every tuple joins the baseline."""
    rng = sc.rng
    docs = ["Q3-report.docx", "budget-2024.xlsx", "minutes.pdf", "roadmap.pptx", "notes.txt"]
    for host in hosts:
        t = start + rng.uniform(0, 1800)
        while t < end:
            name = rng.choice(docs)
            sc.smb_session(
                t,
                host,
                FILE_SERVER,
                "\\\\FS01\\Shares",
                [("SMB::FILE_OPEN", f"Finance\\{name}", rng.randrange(20_000, 900_000))],
                duration=rng.uniform(5, 300),
            )
            t += rng.expovariate(1.0 / 5400)
        t = start + rng.uniform(0, 3600)
        while t < end:
            for port in (445, 135):
                sc.conn(
                    t + (0.5 if port == 135 else 0.0),
                    host,
                    DC,
                    port,
                    service="smb" if port == 445 else "dce_rpc",
                    duration=rng.uniform(0.1, 3),
                    orig_bytes=rng.randrange(500, 5000),
                    resp_bytes=rng.randrange(500, 9000),
                )
                sc.observe(host, DC, port, t)
            t += 3600 + rng.uniform(-300, 300)


def beacon(
    sc: Scenario,
    src: str,
    dst: str,
    port: int,
    start: float,
    count: int,
    interval: float,
    jitter: float,
    *,
    service: str | None,
    req: int,
    resp: int,
    size_jitter: float = 0.03,
    skip: Iterable[int] = (),
) -> tuple[float, float]:
    """Periodic sessions with symmetric uniform jitter; returns (first, last) ts."""
    rng = sc.rng
    skipped = set(skip)
    t = start
    stamps = []
    for i in range(count):
        if i not in skipped:
            sc.conn(
                t,
                src,
                dst,
                port,
                service=service,
                duration=rng.uniform(0.05, 0.4),
                orig_bytes=int(req * (1 + rng.uniform(-size_jitter, size_jitter))),
                resp_bytes=int(resp * (1 + rng.uniform(-0.1, 0.1))),
            )
            stamps.append(round(t, 6))
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return stamps[0], stamps[-1]


def b32_label(rng: random.Random, nbytes: int) -> str:
    return base64.b32encode(rng.randbytes(nbytes)).decode().rstrip("=").lower()


def random_sld(rng: random.Random, lo: int, hi: int) -> str:
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randrange(lo, hi + 1)))


# --- scenarios --------------------------------------------------------------------

WORKSTATIONS = [f"10.1.2.{i}" for i in range(21, 41)]


def scenario_c2_beaconing() -> Scenario:
    start = 1_700_006_400.0  # 2023-11-15T00:00:00Z
    sc = Scenario(
        "c2_beaconing",
        42,
        start,
        "Beaconing true positives (spec scenario `beacon_60s`) over 6 h of benign web "
        "traffic, including an IPv6 variant and two regular-but-benign decoys.",
        {"conn": "tsv", "dns": "tsv"},
    )
    end = start + 6 * HOUR
    web_background(sc, WORKSTATIONS[:15], start, end)
    web_background(sc, ["fd00:10:1:2::30"], start, end)
    first, last = beacon(
        sc,
        "10.1.2.15",
        "203.0.113.40",
        443,
        start + HOUR + 17,
        180,
        60.0,
        0.05,
        service="ssl",
        req=900,
        resp=250,
    )
    sc.label(
        detector="c2_beaconing",
        src="10.1.2.15",
        dst="203.0.113.40",
        indicator="203.0.113.40:443",
        window=[first, last],
        technique_id="T1071.001",
        note="injected 60 s ±5 % jitter HTTPS beacon, ~900 B requests, seed=42",
    )
    first6, last6 = beacon(
        sc,
        "fd00:10:1:2::25",
        "2001:db8:40::10",
        8443,
        start + 2 * HOUR + 5,
        60,
        120.0,
        0.05,
        service="ssl",
        req=640,
        resp=180,
    )
    sc.label(
        detector="c2_beaconing",
        src="fd00:10:1:2::25",
        dst="2001:db8:40::10",
        indicator="[2001:db8:40::10]:8443",
        window=[first6, last6],
        technique_id="T1071.001",
        note="IPv6 variant: 120 s ±5 % beacon to a documentation-prefix C2",
    )
    # Decoy 1: NTP polling (suppressed via service=ntp).
    t = start + 11
    while t < end:
        sc.conn(
            t,
            "10.1.2.20",
            "192.0.2.123",
            123,
            "udp",
            service="ntp",
            duration=0.02,
            orig_bytes=48,
            resp_bytes=48,
        )
        t += 64
    sc.note_benign(
        "NTP polling every 64 s with constant 48 B packets (service=ntp suppression)",
        detector="c2_beaconing",
        src="10.1.2.20",
        dst="192.0.2.123",
    )
    # Decoy 2: update check to an allowlisted vendor endpoint (site.yaml `updates`).
    t = start + 40
    while t < end:
        sc.conn(
            t,
            "10.1.2.30",
            "192.0.2.80",
            443,
            service="ssl",
            duration=0.3,
            orig_bytes=1210,
            resp_bytes=5400,
        )
        t += 300
    sc.note_benign(
        "Exact 300 s update check to an allowlisted vendor CIDR (site.yaml)",
        detector="c2_beaconing",
        src="10.1.2.30",
        dst="192.0.2.80",
    )
    sc.site = {"site": {"networks": {"allowlists": {"updates": ["192.0.2.80/32"]}}}}
    sc.readme = [
        "* 15 IPv4 workstations and one IPv6 workstation browsing with Poisson arrivals "
        "(lognormal sizes) — irregular, must not score.",
        "* **TP**: `10.1.2.15 → 203.0.113.40:443` every 60 s ±5 % for 3 h, ~900 B requests.",
        "* **TP (IPv6)**: `fd00:10:1:2::25 → [2001:db8:40::10]:8443` every 120 s ±5 % for 2 h.",
        "* Decoy: NTP every 64 s (`service=ntp` suppression).",
        "* Decoy: exact 300 s update check to `192.0.2.80`, allowlisted in `site.yaml`.",
    ]
    return sc


def scenario_beacon_jittered() -> Scenario:
    start = 1_700_028_000.0  # 2023-11-15T06:00:00Z
    sc = Scenario(
        "beacon_jittered",
        7,
        start,
        "A 300 s beacon with ±25 % uniform jitter and one missed check-in: exercises the "
        "MAD-based robust CV near the regularity threshold.",
        {"conn": "json"},
    )
    end = start + 5 * HOUR
    web_background(sc, WORKSTATIONS[:10], start, end)
    first, last = beacon(
        sc,
        "10.1.2.44",
        "203.0.113.77",
        80,
        start + 600,
        52,
        300.0,
        0.25,
        service="http",
        req=412,
        resp=96,
        size_jitter=0.05,
        skip=[23],
    )
    sc.label(
        detector="c2_beaconing",
        src="10.1.2.44",
        dst="203.0.113.77",
        indicator="203.0.113.77:80",
        window=[first, last],
        technique_id="T1071.001",
        note="300 s beacon, uniform ±25 % jitter, check-in #23 missed (host asleep)",
    )
    sc.readme = [
        "* 10 workstations browsing (Poisson arrivals).",
        "* **TP**: `10.1.2.44 → 203.0.113.77:80` every 300 s ±25 % (uniform) for ~4.3 h with one "
        "skipped check-in. Only ~12 sessions fall in each 1 h window, so the count component "
        "is low and detection relies on interval/size regularity.",
        "* `conn.log` is Zeek JSON.",
    ]
    return sc


def scenario_dns_tunneling() -> Scenario:
    start = 1_700_049_600.0  # 2023-11-15T12:00:00Z
    sc = Scenario(
        "dns_tunneling",
        1337,
        start,
        "iodine-style TXT tunnel with base32 payload labels (spec scenario `dns_tunnel_txt`) "
        "over 3 h of benign resolver traffic.",
        {"conn": "tsv", "dns": "json"},
    )
    end = start + 3 * HOUR
    dns_background(sc, WORKSTATIONS[:15], start, end, gap=90.0)
    rng = sc.rng
    t = start + 1800 + 3
    stamps = []
    while t < start + 1800 + 4800:
        payload = b32_label(rng, 70)
        name = f"{payload[:56]}.{payload[56:]}.t.example.net"
        answer = b32_label(rng, 110)
        sc.dns(t, "10.1.3.22", name, "TXT", answers=[f"TXT {len(answer)} {answer}"], ttl=0.0)
        stamps.append(round(t, 6))
        t += rng.uniform(3, 9)
    sc.label(
        detector="dns_tunneling",
        src="10.1.3.22",
        indicator="example.net",
        window=[stamps[0], stamps[-1]],
        technique_id="T1071.004",
        note="iodine-style TXT tunnel, base32 subdomains under t.example.net, seed=1337",
    )
    # Decoy: AD service discovery (long names, underscore labels, SRV).
    for i in range(60):
        sc.dns(
            start + 120 * i + 7,
            WORKSTATIONS[i % 15],
            "_ldap._tcp.default-first-site-name._sites.dc._msdcs.corp.example.org",
            "SRV",
            answers=["dc01.corp.example.org"],
        )
    sc.note_benign(
        "Active Directory SRV discovery (_ldap._tcp…) — long names, excluded by "
        "SRV/underscore rules",
        detector="dns_tunneling",
    )
    sc.readme = [
        "* 15 workstations resolving popular (Tranco-allowlisted) names.",
        f"* **TP**: `10.1.3.22` sends {len(stamps)} TXT queries `<base32>.<base32>.t.example.net` "
        "over 80 minutes (3–9 s apart) with base32 TXT answers.",
        "* Decoy: 60 AD `_ldap._tcp…` SRV lookups.",
        "* `dns.log` is Zeek JSON; `conn.log` (UDP/53 flows) is TSV.",
    ]
    return sc


def scenario_dga() -> Scenario:
    start = 1_700_064_000.0  # 2023-11-15T16:00:00Z
    sc = Scenario(
        "dga",
        2024,
        start,
        "NXDOMAIN burst of 40 lexically random domains from one host in ~4 minutes (spec "
        "scenario `dga_burst`) mixed into benign DNS, plus benign NXDOMAIN look-alikes.",
        {"conn": "tsv", "dns": "tsv"},
    )
    end = start + 2 * HOUR
    dns_background(sc, WORKSTATIONS[:15], start, end, gap=120.0)
    rng = sc.rng
    t = start + 1500 + 11
    stamps = []
    tlds = ["com", "net", "org", "info", "biz"]
    for _ in range(40):
        sc.dns(t, "10.1.4.31", f"{random_sld(rng, 10, 16)}.{rng.choice(tlds)}", "A", "NXDOMAIN")
        stamps.append(round(t, 6))
        t += rng.uniform(3, 8)
    live = f"{random_sld(rng, 12, 12)}.com"
    sc.dns(t + 2, "10.1.4.31", live, "A", answers=["203.0.113.66"])
    sc.conn(
        t + 2.5,
        "10.1.4.31",
        "203.0.113.66",
        443,
        service="ssl",
        duration=1.2,
        orig_bytes=640,
        resp_bytes=2200,
    )
    sc.label(
        detector="dga",
        src="10.1.4.31",
        window=[stamps[0], stamps[-1]],
        technique_id="T1568.002",
        note="40 NXDOMAIN lookups of random 10–16 char SLDs, then one resolving name",
    )
    # Decoys
    for host in WORKSTATIONS[:6]:
        base_t = start + rng.uniform(0, 3600)
        for _ in range(3):
            sc.dns(base_t, host, random_sld(rng, 7, 15), "A", "NXDOMAIN")
            base_t += 0.05
    sc.note_benign(
        "Chromium DNS-interception probes: 3 random single-label NXDOMAINs per "
        "browser start (no public suffix → excluded)",
        detector="dga",
    )
    for i in range(30):
        sc.dns(
            start + 600 + i * 2.0,
            "10.1.2.40",
            f"{rng.choice(['wpad', 'printer01', 'isatap', 'fileshare'])}.corp.example.org",
            "A",
            "NXDOMAIN",
        )
    sc.note_benign(
        "Search-suffix expansion storm under corp.example.org (internal zone, and "
        "one registered domain)",
        detector="dga",
        src="10.1.2.40",
    )
    for typo in ["gooogle.com", "micosoft.com", "wikipedai.org"]:
        sc.dns(start + rng.uniform(0, 7000), rng.choice(WORKSTATIONS), typo, "A", "NXDOMAIN")
    sc.note_benign("Occasional typo NXDOMAINs from different hosts", detector="dga")
    sc.site = {"site": {"internal_zones": ["corp.example.org"]}}
    sc.readme = [
        "* 15 workstations resolving popular names.",
        "* **TP**: `10.1.4.31` looks up 40 random `[a-z]{10,16}` names across .com/.net/.org/"
        ".info/.biz (all NXDOMAIN) in ~4 minutes, then resolves one and connects to it.",
        "* Decoys: Chromium random single-label probes, a `corp.example.org` search-suffix storm "
        "(internal zone via `site.yaml`), and scattered typos.",
    ]
    return sc


def scenario_lateral_movement() -> Scenario:
    start = 1_700_096_400.0  # 2023-11-16T01:00:00Z (Thursday)
    sc = Scenario(
        "lateral_movement",
        445,
        start,
        "PsExec-style lateral movement (spec scenario `lateral_psexec`): a new internal SMB "
        "pair plus an executable written to ADMIN$, later an admin-port scan, against a "
        "mature first-seen baseline.",
        {"conn": "tsv", "smb_files": "json"},
    )
    sc.baseline = {}
    sc.baseline_started = start - 14 * DAY
    end = start + 11 * HOUR
    rng = sc.rng
    web_background(sc, WORKSTATIONS[:12], start, end)
    office_smb_and_dc(sc, [*WORKSTATIONS[:12], "10.1.2.15"], start, end)
    # Admin's routine RDP/WinRM to known servers (in baseline).
    for server in ("10.1.5.10", "10.1.5.11", "10.1.0.10"):
        for port in (3389, 5985):
            sc.observe(ADMIN_WS, server, port, start - 3 * DAY)
    t = start + 8.5 * HOUR
    sc.conn(
        t,
        ADMIN_WS,
        "10.1.5.11",
        3389,
        service="rdp",
        duration=1800.0,
        orig_bytes=900_000,
        resp_bytes=12_000_000,
    )

    # Attack 02:10Z (off-hours): new 445 pair + PSEXESVC.exe write to ADMIN$.
    t = start + HOUR + 600 + 7
    oport = sc.eport()
    uid = sc.conn(
        t,
        "10.1.2.15",
        APP_SERVER,
        445,
        service="smb",
        duration=42.0,
        orig_bytes=310_000,
        resp_bytes=24_000,
        oport=oport,
    )
    sc.smb_file(
        t + 0.4,
        uid,
        "10.1.2.15",
        oport,
        APP_SERVER,
        "SMB::FILE_OPEN",
        f"\\\\{APP_SERVER}\\IPC$",
        "svcctl",
        0,
    )
    for action in ("SMB::FILE_OPEN", "SMB::FILE_WRITE"):
        sc.smb_file(
            t + 1.2,
            uid,
            "10.1.2.15",
            oport,
            APP_SERVER,
            action,
            f"\\\\{APP_SERVER}\\ADMIN$",
            "PSEXESVC.exe",
            381_816,
        )
    sc.conn(
        t + 3.0,
        "10.1.2.15",
        APP_SERVER,
        135,
        service="dce_rpc",
        duration=0.8,
        orig_bytes=1_800,
        resp_bytes=1_200,
    )
    sc.label(
        detector="lateral_movement",
        src="10.1.2.15",
        dst=APP_SERVER,
        window=[round(t, 6), round(t + 3.0, 6)],
        technique_id="T1021.002",
        note="new 445/135 pair off-hours + PSEXESVC.exe written to ADMIN$ (signals 1+2 merge)",
    )

    # Discovery 05:30Z: admin-port sweep of 30 hosts, all failed (scan pattern).
    t = start + 4.5 * HOUR + 13
    first = round(t, 6)
    for i in range(30):
        sc.conn(t, "10.1.2.15", f"10.1.6.{i + 1}", 445, state=rng.choice(["S0", "S0", "REJ"]))
        t += rng.uniform(1, 6)
    sc.label(
        detector="lateral_movement",
        src="10.1.2.15",
        window=[first, round(t, 6)],
        technique_id="T1046",
        note="445 sweep of 30 hosts, all S0/REJ → fan-out pattern=scan",
    )

    # Decoy: admin host opens a NEW RDP pair during business hours (score 0.5 < 0.6).
    sc.conn(
        start + 8 * HOUR + 1200,
        ADMIN_WS,
        "10.1.5.30",
        3389,
        service="rdp",
        duration=600.0,
        orig_bytes=300_000,
        resp_bytes=4_000_000,
    )
    sc.note_benign(
        "Admin workstation's first RDP session to a new server during business "
        "hours: new pair but admin host + business hours → 0.5, below threshold",
        detector="lateral_movement",
        src=ADMIN_WS,
        dst="10.1.5.30",
    )
    sc.note_benign(
        "Routine workstation SMB to the file server and DC traffic (in baseline)",
        detector="lateral_movement",
    )
    sc.site = {"site": {"networks": {"admin_hosts": [f"{ADMIN_WS}/32"]}}}
    sc.readme = [
        "* 12 workstations: web browsing, file-server SMB (`\\\\FS01\\Shares`), hourly DC "
        "SMB/RPC — all in the seeded baseline.",
        "* **TP** 02:10Z (off-hours): `10.1.2.15 → 10.1.5.20` — first-ever 445/135 sessions, "
        "`IPC$` svcctl open, then `PSEXESVC.exe` FILE_OPEN + FILE_WRITE on `ADMIN$`.",
        "* **TP** 05:30Z: `10.1.2.15` sweeps 30 hosts on 445; every attempt fails (S0/REJ) → "
        "fan-out tagged `pattern: scan`, T1046.",
        "* Decoy 09:20Z: admin workstation `10.1.8.5` (site `admin_hosts`) opens a new RDP pair "
        "in business hours.",
        "* `smb_files.log` is Zeek JSON; `conn.log` is TSV.",
    ]
    return sc


def scenario_benign_office() -> Scenario:
    start = 1_700_179_200.0  # 2023-11-17T00:00:00Z (Friday)
    sc = Scenario(
        "benign_office",
        99,
        start,
        "24 h of synthetic office traffic (spec scenario `benign_office`): browsing, O365-style "
        "DNS, NTP, update checks, file-server SMB and DC traffic. Pure negative.",
        {"conn": "json", "dns": "tsv", "smb_files": "tsv"},
    )
    sc.baseline = {}
    sc.baseline_started = start - 14 * DAY
    end = start + DAY
    hosts = WORKSTATIONS
    web_background(sc, hosts, start, end, busy_gap=300.0)
    web_background(sc, ["fd00:10:1:2::30", "fd00:10:1:2::31"], start, end, busy_gap=600.0)
    dns_background(sc, hosts[:10], start, end, gap=600.0)
    office_smb_and_dc(sc, hosts, start, end)
    t = start + 5
    while t < end:
        sc.conn(
            t,
            "10.1.2.21",
            "192.0.2.123",
            123,
            "udp",
            service="ntp",
            duration=0.02,
            orig_bytes=48,
            resp_bytes=48,
        )
        t += 1024
    for host in hosts[:5]:
        t = start + sc.rng.uniform(0, 300)
        while t < end:
            sc.conn(
                t,
                host,
                "192.0.2.80",
                443,
                service="ssl",
                duration=0.3,
                orig_bytes=1210,
                resp_bytes=5400,
            )
            t += 300
    sc.note_benign(
        "Five workstations poll an allowlisted update endpoint every 300 s",
        detector="c2_beaconing",
        dst="192.0.2.80",
    )
    sc.site = {"site": {"networks": {"allowlists": {"updates": ["192.0.2.80/32"]}}}}
    sc.readme = [
        "* 20 IPv4 + 2 IPv6 workstations browsing with business-hours load.",
        "* Resolver traffic for popular names; NTP every 1024 s.",
        "* Exact 300 s update checks from 5 hosts to `192.0.2.80` (allowlisted in `site.yaml`).",
        "* File-server SMB and hourly DC SMB/RPC (all in the seeded baseline).",
        "* Formats: `conn.log` JSON, `dns.log` and `smb_files.log` TSV.",
    ]
    return sc


def scenario_fp_traps() -> Scenario:
    start = 1_700_265_600.0  # 2023-11-18T00:00:00Z (Saturday: everything is off-hours)
    sc = Scenario(
        "fp_traps",
        31337,
        start,
        "Known false-positive regression set (spec §7): every behaviour here resembles an "
        "attack signal and must produce zero detections at default thresholds.",
        {"conn": "tsv", "dns": "json", "smb_files": "tsv"},
    )
    sc.baseline = {}
    sc.baseline_started = start - 14 * DAY
    end = start + 6 * HOUR
    rng = sc.rng
    web_background(sc, WORKSTATIONS[:8], start, end, quiet_gap=900.0)

    # 1. CDN cache-busting hostnames.
    t = start + 900
    for _ in range(400):
        sc.dns(
            t,
            "10.1.2.50",
            f"{rng.randbytes(8).hex()}.assets.example.org",
            "A",
            answers=[f"198.51.100.{rng.randrange(60, 90)}"],
            ttl=20.0,
        )
        t += rng.uniform(2, 14)
    sc.note_benign(
        "CDN cache-busting: 400 unique 16-hex-char hostnames under one domain "
        "(high entropy/uniqueness but short, A-only)",
        detector="dns_tunneling",
        src="10.1.2.50",
    )
    # 2. DNSBL lookups by the mail gateway.
    t = start + 60
    for _ in range(500):
        octets = ".".join(str(rng.randrange(1, 255)) for _ in range(4))
        listed = rng.random() < 0.05
        sc.dns(
            t,
            MAIL,
            f"{octets}.zen.spamhaus.org",
            "A",
            "NOERROR" if listed else "NXDOMAIN",
            answers=["127.0.0.2"] if listed else None,
        )
        t += rng.uniform(5, 60)
    sc.note_benign(
        "Mail gateway DNSBL lookups (reversed IPs under zen.spamhaus.org, mostly "
        "NXDOMAIN) — allowlisted registered domain",
        src=MAIL,
    )
    # 3. Kerberos / AD SRV discovery.
    for i in range(120):
        sc.dns(
            start + 150 * i,
            WORKSTATIONS[i % 8],
            "_kerberos._tcp.dc._msdcs.corp.example.org",
            "SRV",
            answers=["dc01.corp.example.org"],
        )
    sc.note_benign("Kerberos SRV discovery (_kerberos._tcp…)", detector="dns_tunneling")
    # 4. IPv6 reverse lookups (dropped at the reader).
    for i in range(80):
        nibbles = ".".join(rng.choice("0123456789abcdef") for _ in range(32))
        sc.dns(start + 200 + 37 * i, "10.1.2.51", f"{nibbles}.ip6.arpa", "PTR", "NXDOMAIN")
    sc.note_benign(
        "ip6.arpa PTR lookups (63+ labels) — .arpa dropped by the reader", src="10.1.2.51"
    )
    # 5. Chromium probes and 6. a dead domain hammered by a misconfigured app.
    for host in WORKSTATIONS[:8]:
        base_t = start + rng.uniform(0, 3000)
        for _ in range(3):
            sc.dns(base_t, host, random_sld(rng, 7, 15), "A", "NXDOMAIN")
            base_t += 0.04
    t = start + 1200
    for _ in range(200):
        sc.dns(t, "10.1.2.60", "telemetry.defunct-vendor.example.org", "A", "NXDOMAIN")
        t += rng.uniform(1, 4)
    sc.note_benign(
        "Misconfigured app hammering one dead name (one registered domain → c_burst 0)",
        detector="dga",
        src="10.1.2.60",
    )
    # 7. NTP polling every 64 s.
    t = start + 3
    while t < end:
        sc.conn(
            t,
            "10.1.2.20",
            "192.0.2.123",
            123,
            "udp",
            service="ntp",
            duration=0.02,
            orig_bytes=48,
            resp_bytes=48,
        )
        t += 64
    sc.note_benign("NTP polling every 64 s", detector="c2_beaconing", src="10.1.2.20")
    # 8. SCCM-style scheduled HTTP to an internal server.
    for host in WORKSTATIONS[:8]:
        t = start + rng.uniform(0, 300)
        while t < end:
            sc.conn(
                t, host, SCCM, 80, service="http", duration=0.2, orig_bytes=820, resp_bytes=1460
            )
            t += 300
    sc.note_benign(
        "SCCM client policy polling every 300 s to an internal server",
        detector="c2_beaconing",
        dst=SCCM,
    )
    # 9. Split long-lived keep-alive session (OTH records back to back).
    t = start + 30
    while t < end:
        sc.conn(
            t,
            "10.1.2.70",
            "203.0.113.99",
            5222,
            service=None,
            duration=29.95,
            orig_bytes=64,
            resp_bytes=64,
            state="OTH",
        )
        t += 30
    sc.note_benign(
        "Long-lived XMPP/MQTT-style keep-alive split by Zeek into back-to-back OTH records",
        detector="c2_beaconing",
        src="10.1.2.70",
    )
    # 10. Vulnerability scanner sweep (site scanner_hosts).
    t = start + 2 * HOUR
    for i in range(1, 121):
        for port in (445, 135, 3389, 22):
            state = rng.choice(["S0", "REJ", "REJ", "SF"])
            sc.conn(
                t,
                SCANNER,
                f"10.1.6.{i}",
                port,
                state=state,
                duration=None if state == "S0" else 0.01,
                orig_bytes=200 if state == "SF" else 0,
                resp_bytes=300 if state == "SF" else 0,
            )
            t += rng.uniform(0.05, 0.5)
        if i % 10 == 0:
            oport = sc.eport()
            uid = sc.conn(
                t,
                SCANNER,
                f"10.1.6.{i}",
                445,
                service="smb",
                duration=2.0,
                orig_bytes=4_000,
                resp_bytes=3_000,
                oport=oport,
            )
            sc.smb_file(
                t + 0.2,
                uid,
                SCANNER,
                oport,
                f"10.1.6.{i}",
                "SMB::FILE_OPEN",
                f"\\\\10.1.6.{i}\\IPC$",
                "srvsvc",
                0,
            )
    sc.note_benign(
        "Credentialed vulnerability scan of 120 hosts on admin ports with IPC$ "
        "access (site scanner_hosts)",
        detector="lateral_movement",
        src=SCANNER,
    )
    # 11. SCCM pushes ccmsetup.exe to ADMIN$ on 30 workstations; backup agent writes to C$.
    t = start + 3 * HOUR
    for i in range(30):
        target = f"10.1.3.{100 + i}"
        sc.smb_session(
            t,
            SCCM,
            target,
            f"\\\\{target}\\ADMIN$",
            [
                ("SMB::FILE_OPEN", "ccmsetup\\ccmsetup.exe", 1_982_464),
                ("SMB::FILE_WRITE", "ccmsetup\\ccmsetup.exe", 1_982_464),
            ],
            observe=False,
        )
        t += rng.uniform(5, 15)
    sc.note_benign(
        "SCCM client push: ccmsetup.exe written to ADMIN$ on 30 hosts in ~5 min "
        "(site lateral_allow_sources, with justification)",
        detector="lateral_movement",
        src=SCCM,
    )
    t = start + 4 * HOUR
    for i in range(12):
        sc.smb_session(
            t,
            BACKUP,
            FILE_SERVER,
            "\\\\FS01\\C$",
            [("SMB::FILE_WRITE", f"Backup\\incr-{i:03d}.bak", 50_000_000)],
            observe=False,
        )
        t += 600
    sc.note_benign(
        "Backup agent writing to C$ on the file server (lateral_allow_sources)",
        detector="lateral_movement",
        src=BACKUP,
    )
    sc.site = {
        "site": {
            "networks": {
                "scanner_hosts": [f"{SCANNER}/32"],
                "lateral_allow_sources": [
                    {
                        "cidr": f"{SCCM}/32",
                        "justification": (
                            "SCCM primary site server: client push installs via ADMIN$"
                        ),
                    },
                    {
                        "cidr": f"{BACKUP}/32",
                        "justification": "Backup server: agentless file-level backups over C$",
                    },
                ],
            },
            "internal_zones": ["corp.example.org"],
        }
    }
    sc.readme = [
        "Each trap maps to a row of spec §7 and to an entry in `labels.json` → `benign`:",
        "",
        "1. CDN cache-busting hostnames (`<hex>.assets.example.org`).",
        "2. DNSBL lookups via `zen.spamhaus.org`.",
        "3. Kerberos SRV discovery.",
        "4. `ip6.arpa` reverse lookups.",
        "5. Chromium random single-label probes.",
        "6. One dead domain hammered by a misconfigured app.",
        "7. NTP polling every 64 s.",
        "8. SCCM-style scheduled HTTP to an internal server.",
        "9. A long-lived keep-alive split into back-to-back OTH records.",
        "10. A credentialed vulnerability scan (scanner listed in `site.yaml`).",
        "11. SCCM pushing `ccmsetup.exe` to `ADMIN$` and a backup agent writing to `C$` "
        "(allowlisted with justifications in `site.yaml`).",
    ]
    return sc


def scenario_harness_tiny() -> Scenario:
    """Tiny fixture with hand-checkable counts for tests/test_harness.py."""
    start = 1_700_438_400.0  # 2023-11-20T00:00:00Z
    sc = Scenario(
        "harness_tiny",
        5,
        start,
        "Minimal scenario with exactly one true positive, one false positive and one false "
        "negative for the dns_tunneling detector, used to unit-test metric computation.",
        {"conn": "tsv", "dns": "tsv"},
    )
    rng = sc.rng
    for host, sub in (("10.9.0.10", "a"), ("10.9.0.11", "b")):
        t = start + 600
        for _ in range(60):
            payload = b32_label(rng, 50)
            sc.dns(
                t,
                host,
                f"{payload}.{sub}.example.net",
                "TXT",
                answers=[f"TXT 40 {b32_label(rng, 25)}"],
                ttl=0.0,
            )
            t += 10
    sc.label(
        detector="dns_tunneling",
        src="10.9.0.10",
        indicator="example.net",
        window=[start + 600, start + 600 + 590],
        note="labeled tunnel → TP",
    )
    sc.label(
        detector="dns_tunneling",
        src="10.9.0.12",
        indicator="example.net",
        window=[start + 600, start + 1200],
        note="no matching traffic → FN",
    )
    sc.note_benign(
        "10.9.0.11 runs an identical but UNLABELED tunnel → counted as FP", src="10.9.0.11"
    )
    sc.readme = [
        "* `10.9.0.10`: 60 TXT tunnel queries in 10 minutes — labeled (expected TP).",
        "* `10.9.0.11`: identical tunnel, not labeled (expected FP).",
        "* label for `10.9.0.12`, which sends no traffic (expected FN).",
    ]
    return sc


SCENARIOS: list[Callable[[], Scenario]] = [
    scenario_benign_office,
    scenario_c2_beaconing,
    scenario_beacon_jittered,
    scenario_dns_tunneling,
    scenario_dga,
    scenario_lateral_movement,
    scenario_fp_traps,
]


#: Test-only scenarios written under tests/data/ instead of fixtures/.
TEST_SCENARIOS: list[Callable[[], Scenario]] = [scenario_harness_tiny]
TEST_DATA = REPO / "tests" / "data"


def generate(root: Path, builders: Sequence[Callable[[], Scenario]] = SCENARIOS) -> list[str]:
    names = []
    for build in builders:
        scenario = build()
        target = root / scenario.name
        if target.exists():
            shutil.rmtree(target)
        scenario.write(root)
        names.append(scenario.name)
    return names


def _compare(a: Path, b: Path) -> list[str]:
    diffs: list[str] = []
    cmp = filecmp.dircmp(a, b)
    diffs += [f"only in committed: {a / n}" for n in cmp.left_only]
    diffs += [f"missing from committed: {a / n}" for n in cmp.right_only]
    _, mismatch, errors = filecmp.cmpfiles(a, b, cmp.common_files, shallow=False)
    diffs += [f"differs: {a / n}" for n in mismatch + errors]
    for sub in cmp.common_dirs:
        diffs += _compare(a / sub, b / sub)
    return diffs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--out", type=Path, default=FIXTURES)
    ap.add_argument("--test-data", type=Path, default=TEST_DATA)
    ap.add_argument("--check", action="store_true", help="verify committed fixtures are current")
    args = ap.parse_args(argv)
    targets = [(args.out, SCENARIOS), (args.test_data, TEST_SCENARIOS)]
    if args.check:
        diffs: list[str] = []
        for root, builders in targets:
            with tempfile.TemporaryDirectory() as tmp:
                names = generate(Path(tmp), builders)
                diffs += [d for n in names for d in _compare(root / n, Path(tmp) / n)]
        for d in diffs:
            print(d, file=sys.stderr)
        if not diffs:
            print("fixtures are up to date")
        return 1 if diffs else 0
    for root, builders in targets:
        names = generate(root, builders)
        print(f"generated {len(names)} scenario(s) under {root}: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
