"""Site policy objects: internal networks, allowlists, business hours.

These are built once from configuration and shared (read-only) by every
analyzer. Lookups are cached because the same handful of addresses recur
millions of times in real conn.log data.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time
from functools import lru_cache
from typing import Any
from zoneinfo import ZoneInfo

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: RFC 1918 private IPv4 space — the code-level default internal definition.
RFC1918: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

_DAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


class PolicyError(ValueError):
    """Raised for malformed policy configuration."""


@lru_cache(maxsize=262_144)
def parse_ip(value: str) -> IPAddress | None:
    """Parse an address, unwrapping IPv4-mapped IPv6; ``None`` if invalid."""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


@lru_cache(maxsize=262_144)
def normalize_ip(value: str) -> str:
    """Canonical (compressed, lower-case) text form; input returned if not an IP."""
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        return value


def format_endpoint(ip: str, port: int) -> str:
    """``ip:port`` with RFC 3986 brackets for IPv6 (``[2001:db8::1]:443``)."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def parse_networks(values: Iterable[str], *, context: str) -> tuple[IPNetwork, ...]:
    nets: list[IPNetwork] = []
    for raw in values:
        try:
            nets.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError as exc:
            raise PolicyError(f"{context}: invalid network {raw!r}: {exc}") from exc
    return tuple(nets)


class NetworkSet:
    """A set of CIDRs with a cached membership test."""

    def __init__(self, networks: Sequence[IPNetwork] = ()) -> None:
        self.networks = tuple(networks)
        self._v4 = tuple(n for n in self.networks if n.version == 4)
        self._v6 = tuple(n for n in self.networks if n.version == 6)
        self._cache: dict[str, bool] = {}

    def __contains__(self, ip: object) -> bool:
        if not isinstance(ip, str):
            return False
        hit = self._cache.get(ip)
        if hit is None:
            addr = parse_ip(ip)
            if addr is None:
                hit = False
            else:
                pool = self._v4 if addr.version == 4 else self._v6
                hit = any(addr in net for net in pool)
            if len(self._cache) < 1_000_000:
                self._cache[ip] = hit
        return hit

    def __bool__(self) -> bool:
        return bool(self.networks)

    def as_strings(self) -> list[str]:
        return [str(n) for n in self.networks]


@dataclass(frozen=True)
class AllowEntry:
    """A source allowlisted for lateral-movement scoring, with its reason."""

    network: IPNetwork
    justification: str


@dataclass
class NetworkPolicy:
    internal: NetworkSet
    allowlists: dict[str, NetworkSet] = field(default_factory=dict)
    admin_hosts: NetworkSet = field(default_factory=NetworkSet)
    scanner_hosts: NetworkSet = field(default_factory=NetworkSet)
    lateral_allow_sources: tuple[AllowEntry, ...] = ()

    def __post_init__(self) -> None:
        self._lateral_allow = NetworkSet([e.network for e in self.lateral_allow_sources])

    @classmethod
    def default(cls) -> NetworkPolicy:
        return cls(internal=NetworkSet(parse_networks(RFC1918, context="default")))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> NetworkPolicy:
        internal_raw = data.get("internal") or list(RFC1918)
        allowlists_raw = data.get("allowlists") or {}
        if not isinstance(allowlists_raw, Mapping):
            raise PolicyError("allowlists must be a mapping of category -> list of CIDRs")
        allowlists = {
            str(cat): NetworkSet(parse_networks(nets or (), context=f"allowlists.{cat}"))
            for cat, nets in allowlists_raw.items()
        }
        entries: list[AllowEntry] = []
        for i, raw in enumerate(data.get("lateral_allow_sources") or ()):
            if not isinstance(raw, Mapping):
                raise PolicyError(
                    f"lateral_allow_sources[{i}] must be a mapping with 'cidr' and 'justification'"
                )
            justification = str(raw.get("justification") or "").strip()
            if not justification:
                raise PolicyError(
                    f"lateral_allow_sources[{i}] ({raw.get('cidr')}) requires a non-empty "
                    "'justification' — allowlisting a source for admin-share activity must "
                    "be documented"
                )
            (net,) = parse_networks([str(raw.get("cidr"))], context="lateral_allow_sources")
            entries.append(AllowEntry(net, justification))
        return cls(
            internal=NetworkSet(parse_networks(internal_raw, context="internal")),
            allowlists=allowlists,
            admin_hosts=NetworkSet(
                parse_networks(data.get("admin_hosts") or (), context="admin_hosts")
            ),
            scanner_hosts=NetworkSet(
                parse_networks(data.get("scanner_hosts") or (), context="scanner_hosts")
            ),
            lateral_allow_sources=tuple(entries),
        )

    def is_internal(self, ip: str) -> bool:
        return ip in self.internal

    def allowlist_category(self, ip: str, categories: Iterable[str] | None = None) -> str | None:
        """Return the first allowlist category containing ``ip``, if any."""
        names = self.allowlists.keys() if categories is None else categories
        for name in names:
            nets = self.allowlists.get(name)
            if nets is not None and ip in nets:
                return name
        return None

    def is_admin_host(self, ip: str) -> bool:
        return ip in self.admin_hosts

    def is_scanner_host(self, ip: str) -> bool:
        return ip in self.scanner_hosts

    def lateral_allowed(self, ip: str) -> AllowEntry | None:
        if ip not in self._lateral_allow:
            return None
        addr = parse_ip(ip)
        for entry in self.lateral_allow_sources:
            if addr is not None and addr in entry.network:
                return entry
        return None

    def fingerprint(self) -> dict[str, Any]:
        return {
            "internal": self.internal.as_strings(),
            "allowlists": {k: v.as_strings() for k, v in sorted(self.allowlists.items())},
            "admin_hosts": self.admin_hosts.as_strings(),
            "scanner_hosts": self.scanner_hosts.as_strings(),
            "lateral_allow_sources": [
                {"cidr": str(e.network), "justification": e.justification}
                for e in self.lateral_allow_sources
            ],
        }


@dataclass
class DomainPolicy:
    """Registered-domain allowlist plus internal DNS zones.

    Allowlist entries are compared against the *registered* domain (PSL-aware)
    by exact match, so allowlisting ``duckdns.org`` does not allowlist
    ``attacker.duckdns.org`` (a separate registrable name under a private
    suffix). Use an explicit ``*.example.com`` entry to allowlist a whole
    subtree regardless of registration boundaries.
    """

    allow: frozenset[str] = frozenset()
    allow_suffixes: tuple[str, ...] = ()
    internal_zones: tuple[str, ...] = ()

    @classmethod
    def from_entries(
        cls, entries: Iterable[str], internal_zones: Iterable[str] = ()
    ) -> DomainPolicy:
        exact: set[str] = set()
        suffixes: set[str] = set()
        for raw in entries:
            entry = raw.strip().lower().rstrip(".")
            if not entry or entry.startswith("#"):
                continue
            if entry.startswith("*."):
                suffixes.add(entry[2:])
            else:
                exact.add(entry)
        zones = tuple(sorted({z.strip().lower().strip(".") for z in internal_zones if z.strip()}))
        return cls(frozenset(exact), tuple(sorted(suffixes)), zones)

    def is_allowlisted(self, registered_domain: str | None, query: str | None = None) -> bool:
        if registered_domain and registered_domain in self.allow:
            return True
        name = query or registered_domain
        if not name:
            return False
        return any(_has_suffix(name, s) for s in self.allow_suffixes)

    def in_internal_zone(self, query: str) -> bool:
        return any(_has_suffix(query, zone) for zone in self.internal_zones)

    def fingerprint(self) -> dict[str, Any]:
        return {
            "allow_count": len(self.allow),
            "allow_digest": _digest(sorted(self.allow)),
            "allow_suffixes": list(self.allow_suffixes),
            "internal_zones": list(self.internal_zones),
        }


def _has_suffix(name: str, suffix: str) -> bool:
    return name == suffix or name.endswith("." + suffix)


def _digest(items: Sequence[str]) -> str:
    import hashlib

    return hashlib.sha256("\n".join(items).encode()).hexdigest()[:16]


@dataclass(frozen=True)
class BusinessHours:
    """Business-hours schedule; the only timezone-aware component (spec §7.5)."""

    tz: str = "UTC"
    days: frozenset[int] = frozenset({0, 1, 2, 3, 4})
    start: time = time(8, 0)
    end: time = time(18, 0)
    holidays: frozenset[date] = frozenset()

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> BusinessHours:
        tz = str(data.get("timezone", "UTC"))
        try:
            ZoneInfo(tz)
        except Exception as exc:
            raise PolicyError(f"unknown timezone {tz!r}") from exc
        raw_days = data.get("days", ["mon", "tue", "wed", "thu", "fri"])
        try:
            days = frozenset(_DAY_NAMES[str(d).lower()[:3]] for d in raw_days)
        except KeyError as exc:
            raise PolicyError(f"invalid day name in schedule: {exc}") from exc
        start = _parse_time(str(data.get("start", "08:00")))
        end = _parse_time(str(data.get("end", "18:00")))
        if end <= start:
            raise PolicyError("business-hours end must be after start (overnight not supported)")
        holidays = frozenset(date.fromisoformat(str(h)) for h in data.get("holidays") or ())
        return cls(tz=tz, days=days, start=start, end=end, holidays=holidays)

    def is_business_hours(self, ts: float) -> bool:
        local = datetime.fromtimestamp(ts, tz=ZoneInfo(self.tz))
        if local.date() in self.holidays or local.weekday() not in self.days:
            return False
        return self.start <= local.time() < self.end

    def fingerprint(self) -> dict[str, Any]:
        return {
            "timezone": self.tz,
            "days": sorted(self.days),
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "holidays": sorted(d.isoformat() for d in self.holidays),
        }


def _parse_time(value: str) -> time:
    try:
        return time.fromisoformat(value)
    except ValueError as exc:
        raise PolicyError(f"invalid time {value!r} (expected HH:MM)") from exc
