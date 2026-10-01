"""Sigma and Suricata exporters (spec §5.3).

Exporters are code, not static files: each analyzer builds its rules from the
live configuration via ``to_sigma()`` / ``to_suricata()``, and the functions
here only serialize them, stamp fidelity tiers and provenance, and write a
manifest. Rule identifiers are deterministic (UUIDv5 over detector, signal
and config hash), so re-exporting an unchanged config is byte-identical and
downstream SIEMs update rules in place.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from zdp import __version__
from zdp.analyzers.base import BaseAnalyzer
from zdp.config import Config
from zdp.exporters.sigma import render_sigma_file
from zdp.exporters.suricata import render_suricata_file
from zdp.registry import available_analyzers, create_analyzers
from zdp.rules import ExportSkip, SigmaRule

FORMATS = ("sigma", "suricata")
GENERATED_PREFIX = "zdp_"


def configured_analyzers(config: Config, names: Sequence[str] | None = None) -> list[BaseAnalyzer]:
    selected = (
        list(names) if names else [n for n in available_analyzers() if config.detector_enabled(n)]
    )
    analyzers = create_analyzers(selected)
    for analyzer in analyzers:
        analyzer.configure(config.analyzer_config(analyzer.name, analyzer.DEFAULTS))
    return analyzers


def stamp_tier(rule: SigmaRule) -> SigmaRule:
    """Declare the fidelity tier in every document's title and description.

    Sigma has no tag namespace for custom metadata (``sigma check`` rejects
    unknown namespaces), so the tier lives in the title, the description and
    the file's ``# zdp-tier:`` header comment.
    """

    def stamp(doc: dict[str, Any]) -> dict[str, Any]:
        out = dict(doc)
        out["title"] = f"{doc['title']} [{rule.tier}]"
        out["description"] = (
            f"zdp fidelity tier: {rule.tier} (see docs/export_fidelity.md). {doc['description']}"
        )
        return out

    return replace(
        rule,
        document=stamp(rule.document),
        companions=tuple(stamp(c) for c in rule.companions),
    )


def _clean(directory: Path, suffix: str) -> None:
    for stale in directory.glob(f"{GENERATED_PREFIX}*{suffix}"):
        stale.unlink()


def export_rules(
    config: Config,
    formats: Sequence[str],
    out_dir: Path,
    detectors: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Write rules under ``out_dir/<format>/`` and ``out_dir/MANIFEST.json``."""
    unknown = set(formats) - set(FORMATS)
    if unknown:
        raise ValueError(f"unknown export formats: {sorted(unknown)}")
    analyzers = configured_analyzers(config, detectors)
    manifest: dict[str, Any] = {
        "generated_by": "zdp export",
        "framework_version": __version__,
        "config_hash": config.config_hash(),
        "files": [],
        "rules": [],
        "skipped": [],
    }
    skips: list[ExportSkip] = [s for a in analyzers for s in a.export_skips()]

    if "sigma" in formats:
        target = out_dir / "sigma"
        target.mkdir(parents=True, exist_ok=True)
        _clean(target, ".yml")
        for analyzer in analyzers:
            sigma_rules = [stamp_tier(r) for r in analyzer.to_sigma()]
            if not sigma_rules and not any(
                s.detector == analyzer.name and s.fmt == "sigma" for s in skips
            ):
                skips.append(
                    ExportSkip(analyzer.name, "*", "sigma", "analyzer defines no Sigma export")
                )
            for rule in sigma_rules:
                path = target / rule.filename
                path.write_text(
                    render_sigma_file(rule, analyzer.config.config_hash), encoding="utf-8"
                )
                manifest["files"].append(str(path.relative_to(out_dir)))
                for doc in (*rule.companions, rule.document):
                    manifest["rules"].append(
                        {
                            "format": "sigma",
                            "detector": rule.detector,
                            "signal": rule.signal,
                            "tier": rule.tier,
                            "id": doc["id"],
                            "title": doc["title"],
                            "kind": "correlation" if "correlation" in doc else "detection",
                            "file": str(path.relative_to(out_dir)),
                        }
                    )

    if "suricata" in formats:
        target = out_dir / "suricata"
        target.mkdir(parents=True, exist_ok=True)
        _clean(target, ".rules")
        seen_sids: dict[int, str] = {}
        for analyzer in analyzers:
            suricata_rules = analyzer.to_suricata()
            if not suricata_rules:
                continue
            for srule in suricata_rules:
                owner = f"{srule.detector}/{srule.signal}"
                if srule.sid in seen_sids:
                    raise RuntimeError(
                        f"SID collision {srule.sid}: {seen_sids[srule.sid]} vs {owner}"
                    )
                seen_sids[srule.sid] = owner
            path = target / f"{GENERATED_PREFIX}{analyzer.name}.rules"
            path.write_text(
                render_suricata_file(analyzer.name, suricata_rules, analyzer.config.config_hash),
                encoding="utf-8",
            )
            manifest["files"].append(str(path.relative_to(out_dir)))
            manifest["rules"] += [
                {
                    "format": "suricata",
                    "detector": r.detector,
                    "signal": r.signal,
                    "tier": r.tier,
                    "sid": r.sid,
                    "file": str(path.relative_to(out_dir)),
                }
                for r in suricata_rules
            ]

    manifest["skipped"] = [
        {"detector": s.detector, "signal": s.signal, "format": s.fmt, "reason": s.reason}
        for s in skips
        if s.fmt in formats
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


__all__ = ["FORMATS", "configured_analyzers", "export_rules"]
