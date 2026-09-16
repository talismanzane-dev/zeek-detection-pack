"""Configuration loading: YAML files, overlays, and per-analyzer views.

Resolution order for the base config file:

1. an explicit path (``--config``);
2. ``$ZDP_CONFIG``;
3. ``config/default.yaml`` in a source checkout;

Relative paths inside a config file (allowlists, schedules) resolve against
that file's directory. Overlays (e.g. a fixture's ``site.yaml``) are
deep-merged on top, so a site can add its scanner hosts without restating
every threshold.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from zdp.models import AnalyzerConfig
from zdp.policy import BusinessHours, DomainPolicy, NetworkPolicy, PolicyError
from zdp.state import AnalyzerState

_PACKAGE_DIR = Path(__file__).resolve().parent
_CANDIDATE_DEFAULTS = (_PACKAGE_DIR.parent / "config" / "default.yaml",)


class ConfigError(ValueError):
    """Raised for invalid or missing configuration."""


def default_config_path() -> Path:
    env = os.environ.get("ZDP_CONFIG")
    if env:
        return Path(env)
    for candidate in _CANDIDATE_DEFAULTS:
        if candidate.is_file():
            return candidate
    raise ConfigError(
        "no configuration found: pass --config, set ZDP_CONFIG, or run from a source checkout"
    )


def deep_merge(base: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` into a copy of ``base`` (lists replace)."""
    out = copy.deepcopy(dict(base))
    for key, value in overlay.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def _read_domain_list(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as fh:
        return [line.split("#", 1)[0].strip() for line in fh if line.split("#", 1)[0].strip()]


def canonical_hash(obj: Any, length: int = 12) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:length]


@dataclass
class Config:
    """Fully resolved configuration (base file + overlays + referenced files)."""

    raw: dict[str, Any]
    networks: NetworkPolicy
    domains: DomainPolicy
    schedule: BusinessHours
    sources: list[str] = field(default_factory=list)

    # -- construction ---------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None, overlays: Sequence[str | Path] = ()) -> Config:
        base_path = Path(path) if path is not None else default_config_path()
        raw = _load_yaml(base_path)
        base_dir = base_path.resolve().parent
        policy_raw = raw.get("policy") or {}

        networks_data = (
            _load_yaml(base_dir / policy_raw["networks_file"])
            if policy_raw.get("networks_file")
            else {}
        )
        domain_entries = (
            _read_domain_list(base_dir / policy_raw["domains_file"])
            if policy_raw.get("domains_file")
            else []
        )
        schedule_data = (
            _load_yaml(base_dir / policy_raw["schedules_file"])
            if policy_raw.get("schedules_file")
            else {}
        )

        sources = [str(base_path)]
        for overlay_path in overlays:
            overlay = _load_yaml(Path(overlay_path))
            sources.append(str(overlay_path))
            # Site overlays may extend policy without replacing the base files.
            site = overlay.pop("site", {}) or {}
            raw = deep_merge(raw, overlay)
            networks_data = deep_merge(networks_data, site.get("networks") or {})
            domain_entries += [str(d) for d in site.get("allow_domains") or ()]
            schedule_data = deep_merge(schedule_data, site.get("schedule") or {})
            if site.get("internal_zones"):
                raw.setdefault("policy", {})
                raw["policy"]["internal_zones"] = list(
                    (raw["policy"].get("internal_zones") or []) + list(site["internal_zones"])
                )

        policy_raw = raw.get("policy") or {}
        try:
            networks = NetworkPolicy.from_mapping(networks_data)
            domains = DomainPolicy.from_entries(
                domain_entries, internal_zones=policy_raw.get("internal_zones") or ()
            )
            schedule = BusinessHours.from_mapping(schedule_data.get("business_hours") or {})
        except PolicyError as exc:
            raise ConfigError(str(exc)) from exc
        return cls(raw=raw, networks=networks, domains=domains, schedule=schedule, sources=sources)

    # -- accessors --------------------------------------------------------------

    @property
    def include_psl_private_domains(self) -> bool:
        return bool((self.raw.get("policy") or {}).get("include_psl_private_domains", True))

    @property
    def drop_arpa(self) -> bool:
        return bool((self.raw.get("reader") or {}).get("drop_arpa", True))

    @property
    def runner(self) -> dict[str, Any]:
        return dict(self.raw.get("runner") or {})

    def detector_params(self, name: str, defaults: Mapping[str, Any]) -> dict[str, Any]:
        configured = (self.raw.get("detectors") or {}).get(name) or {}
        unknown = set(configured) - set(defaults) - {"enabled"}
        if unknown:
            raise ConfigError(f"detectors.{name}: unknown parameters {sorted(unknown)}")
        return deep_merge(defaults, {k: v for k, v in configured.items() if k != "enabled"})

    def detector_enabled(self, name: str) -> bool:
        section = (self.raw.get("detectors") or {}).get(name) or {}
        return bool(section.get("enabled", True))

    def export_settings(self) -> dict[str, Any]:
        return dict(self.raw.get("export") or {})

    def policy_fingerprint(self) -> dict[str, Any]:
        return {
            "networks": self.networks.fingerprint(),
            "domains": self.domains.fingerprint(),
            "schedule": self.schedule.fingerprint(),
            "include_psl_private_domains": self.include_psl_private_domains,
        }

    def config_hash(self) -> str:
        """Hash of the effective configuration, including referenced policy files."""
        return canonical_hash({"raw": self.raw, "policy": self.policy_fingerprint()})

    def analyzer_config(
        self,
        name: str,
        defaults: Mapping[str, Any],
        state: AnalyzerState | None = None,
    ) -> AnalyzerConfig:
        params = self.detector_params(name, defaults)
        digest = canonical_hash({"detector": name, "params": params, **self.policy_fingerprint()})
        return AnalyzerConfig(
            name=name,
            params=params,
            networks=self.networks,
            domains=self.domains,
            schedule=self.schedule,
            include_psl_private_domains=self.include_psl_private_domains,
            state=state,
            config_hash=digest,
        )
