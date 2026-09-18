"""Public Suffix List–aware domain splitting, offline.

Grouping DNS activity by *registered* domain (``example.co.uk``, not
``co.uk``; ``bucket.s3.amazonaws.com``, not ``amazonaws.com``) is central to
both the tunneling and DGA detectors. We use the suffix-list snapshot that
ships inside ``tldextract`` and never touch the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import tldextract


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

    def __init__(self, *, include_private: bool = True) -> None:
        self.include_private = include_private
        self._extract = tldextract.TLDExtract(
            cache_dir=None,
            suffix_list_urls=(),
            fallback_to_snapshot=True,
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
        """Suffix-list provenance (the snapshot bundled with tldextract)."""
        return "tldextract-snapshot"


@lru_cache(maxsize=4)
def get_parser(include_private: bool = True) -> DomainParser:
    return DomainParser(include_private=include_private)
