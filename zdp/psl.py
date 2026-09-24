"""Public Suffix List–aware domain splitting, fully offline.

Grouping DNS activity by *registered* domain (``example.co.uk``, not
``co.uk``; ``bucket.s3.amazonaws.com``, not ``amazonaws.com``) is central to
both the tunneling and DGA detectors. We use ``tldextract`` against the PSL
snapshot pinned in ``zdp/data/public_suffix_list.dat`` and never touch the
network, so results are reproducible and air-gap safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import tldextract

DATA_DIR = Path(__file__).resolve().parent / "data"
PSL_PATH = DATA_DIR / "public_suffix_list.dat"


@dataclass(frozen=True)
class DomainParts:
    subdomain: str
    sld: str
    suffix: str

    @property
    def registered(self) -> str | None:
        if not self.sld or not self.suffix:
            return None
        return f"{self.sld}.{self.suffix}"


class DomainParser:
    """Split names into subdomain / second-level label / public suffix."""

    def __init__(self, psl_path: Path = PSL_PATH, *, include_private: bool = True) -> None:
        if not psl_path.is_file():
            raise FileNotFoundError(f"pinned Public Suffix List not found: {psl_path}")
        self.psl_path = psl_path
        self.include_private = include_private
        self._extract = tldextract.TLDExtract(
            cache_dir=None,
            suffix_list_urls=(psl_path.resolve().as_uri(),),
            fallback_to_snapshot=False,
            include_psl_private_domains=include_private,
        )
        self.split = lru_cache(maxsize=131_072)(self._split)

    def _split(self, name: str) -> DomainParts:
        cleaned = name.strip().lower().rstrip(".")
        if not cleaned:
            return DomainParts("", "", "")
        result = self._extract(cleaned)
        return DomainParts(result.subdomain, result.domain, result.suffix)

    def registered_domain(self, name: str) -> str | None:
        return self.split(name).registered

    def subdomain(self, name: str) -> str:
        return self.split(name).subdomain

    def version(self) -> str:
        """The ``VERSION:`` line from the pinned PSL header, if present."""
        with self.psl_path.open(encoding="utf-8") as fh:
            for _, line in zip(range(40), fh, strict=False):
                if line.startswith("// VERSION:"):
                    return line.split(":", 1)[1].strip()
        return "unknown"


@lru_cache(maxsize=4)
def get_parser(include_private: bool = True) -> DomainParser:
    return DomainParser(include_private=include_private)
