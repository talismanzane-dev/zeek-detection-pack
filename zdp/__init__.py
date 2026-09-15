"""Zeek Detection Pack (zdp): windowed batch detection analytics over Zeek logs."""

__version__ = "0.1.0"

#: Fixed date stamped into exported rules. Tied to the release rather than the
#: wall clock so that re-exporting with an unchanged config is byte-identical.
__release_date__ = "2026-10-11"

__all__ = ["__release_date__", "__version__"]
