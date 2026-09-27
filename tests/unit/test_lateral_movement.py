"""Lateral movement analyzer (spec §2.4, §7.4) including state-store warm-up."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.conftest import configure, conn, window
from zdp.analyzers.lateral_movement import LateralMovementAnalyzer, normalize_unc
from zdp.config import Config
from zdp.state import StateStore

DAY = 86_400.0
NIGHT = 1_700_096_400.0  # 2023-11-16T01:00Z, Thursday (off-hours)
DAYTIME = NIGHT + 9 * 3600  # 10:00Z (business hours)
SRC, DST = "10.1.2.15", "10.1.5.20"


def smb(
    ts: float, action: str, path: str, name: str, src: str = SRC, dst: str = DST
) -> dict[str, Any]:
    return {
        "ts": ts,
        "uid": "Csmb",
        "id.orig_h": src,
        "id.resp_h": dst,
        "id.resp_p": 445,
        "action": action,
        "path": path,
        "name": name,
        "size": 381_816,
    }


def site_config(tmp_path: Path, **networks: Any) -> Config:
    overlay = tmp_path / "site.yaml"
    overlay.write_text(yaml.safe_dump({"site": {"networks": networks}}))
    return Config.load(None, [overlay])


def mature(state: StateStore, now: float, known: tuple[str, ...] = ()) -> None:
    scope = state.scoped("lateral_movement")
    scope.ensure_baseline_started(now - 14 * DAY)
    for key in known:
        scope.observe(key, now - 3 * DAY)


def analyzer(config: Config, state: StateStore, **overrides: Any) -> LateralMovementAnalyzer:
    return configure(LateralMovementAnalyzer(), config, state, **overrides)  # type: ignore[return-value]


class TestNewPair:
    def test_warmup_emits_nothing_but_builds_baseline(
        self, config: Config, state: StateStore
    ) -> None:
        a = analyzer(config, state)
        assert a.analyze(window(NIGHT, conn=[conn(NIGHT + 10, SRC, DST, 445)])) == []
        status = a.status()
        assert status["baseline_warmup"] is True
        assert status["baseline_entries"] == 1
        assert state.scoped("lateral_movement").is_known(f"{SRC}|{DST}|445")

    def test_off_hours_non_admin_scores_highest(self, config: Config, state: StateStore) -> None:
        mature(state, NIGHT)
        (det,) = analyzer(config, state).analyze(
            window(NIGHT, conn=[conn(NIGHT + 10, SRC, DST, 445)])
        )
        assert det.confidence == pytest.approx(0.5 + 0.2 + 0.15)
        assert (det.technique_id, det.tactic, det.indicator) == (
            "T1021.002",
            "Lateral Movement",
            f"{DST}:445",
        )
        assert det.evidence["components"] == {
            "base": 0.5,
            "non_admin_host_bonus": 0.2,
            "off_hours_bonus": 0.15,
        }

    def test_business_hours_and_admin_host(self, tmp_path: Path, state: StateStore) -> None:
        cfg = site_config(tmp_path, admin_hosts=["10.1.8.5/32"])
        mature(state, DAYTIME)
        a = analyzer(cfg, state)
        dets = a.analyze(
            window(
                DAYTIME,
                conn=[
                    conn(DAYTIME + 10, SRC, DST, 3389),
                    conn(DAYTIME + 20, "10.1.8.5", DST, 3389),
                ],
            )
        )
        # Non-admin in business hours: 0.7 (emitted). Admin host: 0.5 (< 0.6, suppressed).
        assert [(d.src, d.confidence, d.technique_id) for d in dets] == [(SRC, 0.7, "T1021.001")]

    def test_known_pair_and_failed_attempts_ignored(
        self, config: Config, state: StateStore
    ) -> None:
        mature(state, NIGHT, known=(f"{SRC}|{DST}|445",))
        records = [
            conn(NIGHT + 10, SRC, DST, 445),
            conn(NIGHT + 20, SRC, "10.1.5.21", 445, conn_state="S0"),
        ]
        assert analyzer(config, state).analyze(window(NIGHT, conn=records)) == []

    def test_multiple_new_ports_on_one_pair_collapse(
        self, config: Config, state: StateStore
    ) -> None:
        mature(state, NIGHT)
        records = [conn(NIGHT + 10, SRC, DST, 135), conn(NIGHT + 15, SRC, DST, 445)]
        (det,) = analyzer(config, state).analyze(window(NIGHT, conn=records))
        assert det.evidence["resp_ports"] == [445, 135]  # config priority order
        assert det.technique_id == "T1021.002"

    def test_baseline_expiry(self, config: Config, state: StateStore) -> None:
        scope = state.scoped("lateral_movement")
        scope.ensure_baseline_started(NIGHT - 60 * DAY)
        scope.observe(f"{SRC}|{DST}|445", NIGHT - 45 * DAY)  # older than 30-day expiry
        a = analyzer(config, state)
        a.analyze(window(NIGHT, conn=[conn(NIGHT + 10, "10.1.2.99", DST, 22)]))
        assert not scope.is_known(f"{SRC}|{DST}|445")


class TestAdminShare:
    def test_exec_write_and_merge_with_new_pair(self, config: Config, state: StateStore) -> None:
        mature(state, NIGHT)
        records = {
            "conn": [conn(NIGHT + 10, SRC, DST, 445)],
            "smb_files": [
                smb(NIGHT + 11, "SMB::FILE_OPEN", f"\\\\{DST}\\IPC$", "svcctl"),
                smb(NIGHT + 12, "SMB::FILE_OPEN", f"\\\\{DST}\\ADMIN$", "PSEXESVC.exe"),
                smb(NIGHT + 12, "SMB::FILE_WRITE", f"\\\\{DST}\\ADMIN$", "PSEXESVC.exe"),
            ],
        }
        (det,) = analyzer(config, state).analyze(window(NIGHT, **records))
        assert det.evidence["signal"] == "new_admin_pair+admin_share_write"
        merge = det.evidence["merge"]
        assert (merge["c1"], merge["c2"]) == (pytest.approx(0.85), 0.9)
        assert det.confidence == 1.0  # min(0.85 + 0.5·0.9, 1)
        assert det.indicator == f"\\\\{DST}\\ADMIN$\\PSEXESVC.exe"
        share = det.evidence["admin_share_write"]
        assert share["ipc_access_count"] == 1
        assert share["secondary_techniques"] == [
            {"tactic": "Lateral Movement", "technique_id": "T1570"}
        ]

    @pytest.mark.parametrize(
        ("action", "path", "name", "expected"),
        [
            ("SMB::FILE_WRITE", "\\\\h\\ADMIN$", "x.exe", 0.9),
            ("SMB::FILE_OPEN", "\\\\h\\C$", "Windows\\Temp\\run.ps1", 0.75),
            ("SMB::FILE_WRITE", "\\\\h\\D$", "notes.txt", 0.6),
            ("SMB::FILE_OPEN", "\\\\h\\ADMIN$", "notes.txt", None),  # read of a non-executable
            ("SMB::FILE_WRITE", "\\\\FS01\\Shares", "x.exe", None),  # not an admin share
            ("SMB::FILE_OPEN", "\\\\h\\IPC$", "srvsvc", None),  # IPC$ alone is not scored
            ("SMB::FILE_WRITE", "\\\\\\\\h\\\\ADMIN$", "x.exe", 0.9),  # escaped form normalized
        ],
    )
    def test_scoring_table(
        self,
        config: Config,
        state: StateStore,
        action: str,
        path: str,
        name: str,
        expected: float | None,
    ) -> None:
        dets = analyzer(config, state).analyze(
            window(NIGHT, conn=[], smb_files=[smb(NIGHT + 5, action, path, name)])
        )
        assert [d.confidence for d in dets] == ([] if expected is None else [expected])

    def test_allowlisted_deployment_server(self, tmp_path: Path, state: StateStore) -> None:
        cfg = site_config(
            tmp_path, lateral_allow_sources=[{"cidr": f"{SRC}/32", "justification": "SCCM"}]
        )
        rec = smb(NIGHT + 5, "SMB::FILE_WRITE", "\\\\h\\ADMIN$", "ccmsetup.exe")
        assert analyzer(cfg, state).analyze(window(NIGHT, conn=[], smb_files=[rec])) == []

    def test_normalize_unc(self) -> None:
        assert normalize_unc("\\\\\\\\host\\\\ADMIN$") == "\\\\host\\ADMIN$"
        assert normalize_unc("\\\\host\\ADMIN$") == "\\\\host\\ADMIN$"


class TestFanout:
    def sweep(self, n: int, state_: str = "S0", src: str = SRC) -> list[dict[str, Any]]:
        return [
            conn(NIGHT + 100 + 5 * i, src, f"10.1.6.{i + 1}", 445, conn_state=state_)
            for i in range(n)
        ]

    def test_scan_pattern_maps_to_discovery_with_reduced_severity(
        self, config: Config, state: StateStore
    ) -> None:
        (det,) = analyzer(config, state).analyze(window(NIGHT, conn=self.sweep(30)))
        assert det.confidence == pytest.approx(0.4 + 20 / 50)
        assert det.technique_id == "T1046" and det.tactic == "Discovery"
        assert det.severity == "low"  # 0.8 → medium, reduced one band
        assert det.evidence["pattern"] == "scan"
        assert det.dst is None and det.indicator == SRC

    def test_access_pattern(self, config: Config, state: StateStore) -> None:
        (det,) = analyzer(config, state).analyze(window(NIGHT, conn=self.sweep(25, "SF")))
        assert det.evidence["pattern"] == "access"
        assert det.technique_id == "T1021.002"

    def test_below_emission_threshold(self, config: Config, state: StateStore) -> None:
        # 15 hosts → 0.4 + 5/50 = 0.5 < min_confidence.
        assert analyzer(config, state).analyze(window(NIGHT, conn=self.sweep(15))) == []

    def test_scanner_host_excluded(self, tmp_path: Path, state: StateStore) -> None:
        cfg = site_config(tmp_path, scanner_hosts=[f"{SRC}/32"])
        assert analyzer(cfg, state).analyze(window(NIGHT, conn=self.sweep(60))) == []


def test_exports(config: Config, state: StateStore) -> None:
    a = analyzer(config, state)
    share, fanout = a.to_sigma()
    assert share.tier == "full" and fanout.tier == "approx"
    assert fanout.document["correlation"]["condition"] == {"gte": 20, "field": "id.resp_h"}
    sur = {r.signal: r for r in a.to_suricata()}
    assert set(sur) == {"admin_share_connect", "admin_share_exec_transfer", "fanout"}
    assert "count 20, seconds 600" in sur["fanout"].text
    assert {(s.signal, s.fmt) for s in a.export_skips()} == {
        ("new_admin_pair", "sigma"),
        ("new_admin_pair", "suricata"),
    }
