"""Analyzer discovery via the ``zdp.analyzers`` entry-point group."""

from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable
from importlib.metadata import entry_points

from zdp.analyzers.base import BaseAnalyzer

LOG = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "zdp.analyzers"

#: Built-ins, used when running from a source tree without an installed
#: distribution (entry points are then unavailable).
BUILTIN_ANALYZERS: dict[str, str] = {
    "c2_beaconing": "zdp.analyzers.c2_beaconing:C2BeaconingAnalyzer",
    "dns_tunneling": "zdp.analyzers.dns_tunneling:DNSTunnelingAnalyzer",
    "dga": "zdp.analyzers.dga:DGAAnalyzer",
}


class RegistryError(LookupError):
    pass


def _load(target: str) -> type[BaseAnalyzer]:
    module_name, _, attr = target.partition(":")
    obj = getattr(importlib.import_module(module_name), attr)
    if not (isinstance(obj, type) and issubclass(obj, BaseAnalyzer)):
        raise RegistryError(f"{target} is not a BaseAnalyzer subclass")
    return obj


def available_analyzers() -> dict[str, type[BaseAnalyzer]]:
    """Map slug → analyzer class (entry points override built-ins of the same name)."""
    found: dict[str, type[BaseAnalyzer]] = {name: _load(t) for name, t in BUILTIN_ANALYZERS.items()}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            cls = ep.load()
        except Exception:
            LOG.exception("failed to load analyzer entry point %s", ep.name)
            continue
        if isinstance(cls, type) and issubclass(cls, BaseAnalyzer):
            found[ep.name] = cls
        else:
            LOG.warning("entry point %s does not reference a BaseAnalyzer subclass", ep.name)
    for name, cls in found.items():
        if cls.name != name:
            raise RegistryError(f"analyzer registered as {name!r} declares name {cls.name!r}")
    return dict(sorted(found.items()))


def create_analyzers(names: Iterable[str] | None = None) -> list[BaseAnalyzer]:
    registry = available_analyzers()
    selected = list(registry) if names is None else list(names)
    unknown = [n for n in selected if n not in registry]
    if unknown:
        raise RegistryError(f"unknown analyzers {unknown}; available: {sorted(registry)}")
    return [registry[name]() for name in selected]


def applicable(analyzers: Iterable[BaseAnalyzer], present_logs: set[str]) -> list[BaseAnalyzer]:
    """Analyzers whose ``required_logs`` are all present."""
    return [a for a in analyzers if a.required_logs <= present_logs]
