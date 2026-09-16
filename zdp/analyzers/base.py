"""The analyzer interface (spec §1.3)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from zdp.models import AnalyzerConfig, Detection, LogWindow
from zdp.rules import ExportSkip, SigmaRule, SuricataRule

if TYPE_CHECKING:
    from zdp.config import Config
    from zdp.state import StateStore


class AnalyzerNotConfiguredError(RuntimeError):
    pass


class BaseAnalyzer(ABC):
    """Base class for all detectors.

    Subclasses declare their slug, required Zeek logs and default parameters,
    and implement :meth:`analyze` over one :class:`LogWindow`. Analyzers must
    treat windows as forward-only streams of records: no random access, no
    look-ahead beyond the window. Anything that must survive across windows
    belongs in ``config.state`` (a :class:`~zdp.state.AnalyzerState`).
    """

    name: ClassVar[str]
    required_logs: ClassVar[frozenset[str]]
    #: Logs consumed when present but not required for the analyzer to run.
    optional_logs: ClassVar[frozenset[str]] = frozenset()
    #: Default parameters. ``config/default.yaml`` mirrors these exactly
    #: (enforced by a unit test) so documentation and code cannot drift.
    DEFAULTS: ClassVar[Mapping[str, Any]]

    def __init__(self) -> None:
        self._config: AnalyzerConfig | None = None

    # -- lifecycle --------------------------------------------------------------

    def configure(self, config: AnalyzerConfig) -> None:
        self._config = config
        self.validate_config(config)

    @property
    def config(self) -> AnalyzerConfig:
        if self._config is None:
            raise AnalyzerNotConfiguredError(f"{self.name}: configure() has not been called")
        return self._config

    @property
    def window_seconds(self) -> int:
        return self.config.window_seconds if self._config else int(self.DEFAULTS["window_seconds"])

    def validate_config(self, config: AnalyzerConfig) -> None:  # noqa: B027 - optional hook
        """Hook for subclasses to reject invalid parameters early."""

    @abstractmethod
    def analyze(self, window: LogWindow) -> list[Detection]:
        """Return detections for one window (may be empty)."""

    def status(self) -> dict[str, Any]:
        """Analyzer-specific run status (e.g. baseline warm-up) for runner output."""
        return {}

    # -- export -----------------------------------------------------------------

    def to_sigma(self) -> list[SigmaRule]:
        return []

    def to_suricata(self) -> list[SuricataRule]:
        return []

    def export_skips(self) -> list[ExportSkip]:
        """Signals that cannot be exported, with the reason (emitted as notices)."""
        return []

    # -- convenience ------------------------------------------------------------

    @classmethod
    def run_on_directory(
        cls,
        log_dir: str | Path,
        config: Config | None = None,
        state: StateStore | None = None,
    ) -> list[Detection]:
        """Run only this analyzer over a Zeek log directory."""
        from zdp.config import Config as _Config
        from zdp.pipeline import Pipeline

        resolved = config if config is not None else _Config.load()
        pipeline = Pipeline(resolved, analyzers=[cls()], state=state)
        return pipeline.run(log_dir).detections
