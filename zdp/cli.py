"""Command-line entry point: ``zdp run | export | harness | list | view | selftest``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from zdp import __version__
from zdp.config import Config, ConfigError
from zdp.models import Detection
from zdp.pipeline import Pipeline
from zdp.registry import available_analyzers, create_analyzers
from zdp.state import StateStore

LOG = logging.getLogger("zdp")


def _add_config_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", type=Path, help="base config (default: config/default.yaml)")
    p.add_argument(
        "--overlay",
        type=Path,
        action="append",
        default=[],
        help="site overlay YAML deep-merged on top of the base config (repeatable)",
    )


def _detector_list(raw: str | None) -> list[str] | None:
    return [d.strip() for d in raw.split(",") if d.strip()] if raw else None


def _write_detections(detections: Sequence[Detection], out: Path | None) -> None:
    if out is None:
        for det in detections:
            sys.stdout.write(det.to_json() + "\n")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for det in detections:
            fh.write(det.to_json() + "\n")
    tmp.replace(out)


def _snapshot(log_dir: Path) -> tuple[tuple[str, float, int], ...]:
    files = sorted(p for p in log_dir.rglob("*.log*") if p.is_file())
    return tuple((str(p), p.stat().st_mtime, p.stat().st_size) for p in files)


def cmd_run(args: argparse.Namespace) -> int:
    """Run detectors once, or repeatedly with ``--watch``.

    Without ``--state`` every run starts from a fresh in-memory store (plus the
    optional ``--state-seed``), so re-processing a growing log directory is
    idempotent. With ``--state`` the SQLite baseline persists across runs;
    feed each log file through it once (e.g. one rotated directory per run).
    """
    config = Config.load(args.config, args.overlay)
    names = _detector_list(args.detectors)
    persistent = StateStore(args.state) if args.state else None
    if persistent is not None and args.state_seed:
        persistent.import_seed_file(args.state_seed)
    last: tuple[tuple[str, float, int], ...] | None = None
    try:
        while True:
            snapshot = _snapshot(args.logs) if args.logs.is_dir() else None
            if snapshot is None or snapshot != last:
                state = persistent
                if state is None:
                    state = StateStore(":memory:")
                    if args.state_seed:
                        state.import_seed_file(args.state_seed)
                pipeline = Pipeline(
                    config, analyzers=create_analyzers(names) if names else None, state=state
                )
                result = pipeline.run(args.logs)
                _write_detections(result.detections, args.out)
                if args.summary:
                    args.summary.parent.mkdir(parents=True, exist_ok=True)
                    args.summary.write_text(
                        json.dumps(result.summary(), indent=2) + "\n", encoding="utf-8"
                    )
                LOG.info(
                    "%d detections from %s (analyzers: %s; skipped: %s)",
                    len(result.detections),
                    args.logs,
                    ",".join(result.analyzers_run) or "none",
                    result.analyzers_skipped or "none",
                )
                for name, status in result.analyzer_status.items():
                    if status:
                        LOG.info("%s status: %s", name, status)
                if state is not persistent:
                    state.close()
                last = snapshot
            if not args.watch:
                return 0
            time.sleep(args.interval)
    finally:
        if persistent is not None:
            persistent.close()


def cmd_export(args: argparse.Namespace) -> int:
    from zdp.exporters import export_rules

    config = Config.load(args.config, args.overlay)
    formats = ["sigma", "suricata"] if args.format == "all" else [args.format]
    manifest = export_rules(config, formats, args.out, detectors=_detector_list(args.detectors))
    for skip in manifest["skipped"]:
        LOG.warning(
            "not exported to %s: %s/%s — %s",
            skip["format"],
            skip["detector"],
            skip["signal"],
            skip["reason"],
        )
    LOG.info("wrote %d rule files under %s", len(manifest["files"]), args.out)
    return 0


def cmd_harness(args: argparse.Namespace) -> int:
    from zdp.harness.runner import main as harness_main

    return harness_main(args.harness_args)


def cmd_list(args: argparse.Namespace) -> int:
    for name, cls in available_analyzers().items():
        logs = ",".join(sorted(cls.required_logs))
        optional = ",".join(sorted(cls.optional_logs))
        suffix = f" (optional: {optional})" if optional else ""
        print(f"{name:20s} requires: {logs}{suffix}")
    return 0


def _render(det: dict[str, object], out: TextIO) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(str(det["ts"]))))
    out.write(
        f"{ts}  {str(det['severity']).upper():6s} {float(str(det['confidence'])):.2f}  "
        f"{det['detector']:16s} {det['technique_id']:10s} {det['src']} -> "
        f"{det.get('dst') or '-'}  {det['indicator']}\n"
    )


def cmd_view(args: argparse.Namespace) -> int:
    position = 0
    while True:
        if args.file.exists():
            with args.file.open(encoding="utf-8") as fh:
                if args.file.stat().st_size < position:
                    position = 0  # file was rewritten
                fh.seek(position)
                while raw := fh.readline():
                    if raw.strip():
                        _render(json.loads(raw), sys.stdout)
                position = fh.tell()
            sys.stdout.flush()
        if not args.follow:
            return 0
        time.sleep(args.interval)


def cmd_selftest(_: argparse.Namespace) -> int:
    """Fast end-to-end smoke test used by the Docker HEALTHCHECK."""
    from zdp.analyzers.c2_beaconing import C2BeaconingAnalyzer
    from zdp.models import LogWindow

    config = Config.load()
    analyzer = C2BeaconingAnalyzer()
    analyzer.configure(config.analyzer_config(analyzer.name, analyzer.DEFAULTS))
    records = [
        {
            "ts": 1_700_000_000.0 + 60 * i,
            "uid": f"Cselftest{i}",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "203.0.113.9",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "orig_bytes": 900,
            "resp_bytes": 300,
            "conn_state": "SF",
            "duration": 0.4,
        }
        for i in range(40)
    ]
    window = LogWindow(1_699_999_200.0, 1_700_002_800.0, {"conn": records})
    detections = analyzer.analyze(window)
    if len(detections) != 1:
        print("selftest FAILED", file=sys.stderr)
        return 1
    print(f"selftest ok (zdp {__version__})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zdp", description="Zeek Detection Pack")
    parser.add_argument("--version", action="version", version=f"zdp {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run detectors over a Zeek log directory")
    run.add_argument("--logs", type=Path, required=True, help="Zeek log directory (recursive)")
    run.add_argument("--out", type=Path, help="detections JSONL (default: stdout)")
    run.add_argument("--detectors", help="comma-separated subset of detectors")
    run.add_argument("--state", type=Path, help="SQLite StateStore for cross-run baselines")
    run.add_argument("--state-seed", type=Path, help="JSON baseline seed to import first")
    run.add_argument("--summary", type=Path, help="write run summary JSON here")
    run.add_argument("--watch", action="store_true", help="re-run when logs change")
    run.add_argument("--interval", type=float, default=60.0, help="watch poll interval (s)")
    _add_config_args(run)
    run.set_defaults(func=cmd_run)

    export = sub.add_parser("export", help="export Sigma / Suricata rules from live config")
    export.add_argument("--format", choices=["sigma", "suricata", "all"], default="all")
    export.add_argument("--out", type=Path, default=Path("rules"))
    export.add_argument("--detectors", help="comma-separated subset of detectors")
    _add_config_args(export)
    export.set_defaults(func=cmd_export)

    harness = sub.add_parser(
        "harness", help="run the labeled-fixture harness (see: zdp harness --help)", add_help=False
    )
    harness.add_argument("harness_args", nargs=argparse.REMAINDER)
    harness.set_defaults(func=cmd_harness)

    lst = sub.add_parser("list", help="list registered analyzers")
    lst.set_defaults(func=cmd_list)

    view = sub.add_parser("view", help="pretty-print a detections JSONL file")
    view.add_argument("file", type=Path)
    view.add_argument("-f", "--follow", action="store_true")
    view.add_argument("--interval", type=float, default=2.0)
    view.set_defaults(func=cmd_view)

    selftest = sub.add_parser("selftest", help="quick smoke test (Docker HEALTHCHECK)")
    selftest.set_defaults(func=cmd_selftest)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw[:1] == ["harness"]:
        # Hand everything after "harness" to the harness's own parser
        # (argparse REMAINDER cannot capture leading --options).
        from zdp.harness.runner import main as harness_main

        return harness_main(raw[1:])
    args = build_parser().parse_args(raw)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return int(args.func(args))
    except (ConfigError, FileNotFoundError) as exc:
        LOG.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
