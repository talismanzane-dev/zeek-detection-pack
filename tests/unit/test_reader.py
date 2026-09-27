"""Zeek log parsing edge cases (spec §4.5)."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from zdp.reader import (
    ReadStats,
    ZeekLogReader,
    detect_format,
    discover_logs,
    iter_file,
    scan_time_bounds,
    unescape_zeek,
)

TSV_HEADER = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
    "#open\t2023-11-15-00-00-00\n"
    "#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes"
    "\tconn_state\tlocal_orig\ttunnel_parents\n"
    "#types\ttime\tstring\taddr\taddr\tport\tenum\tstring\tinterval\tcount\tstring\tbool\tset[string]\n"
)


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_detect_format() -> None:
    assert detect_format("#separator \\x09") == "tsv"
    assert detect_format('{"ts": 1}') == "json"
    with pytest.raises(ValueError):
        detect_format("garbage")


def test_tsv_types_unset_and_empty(tmp_path: Path) -> None:
    path = write(
        tmp_path / "conn.log",
        TSV_HEADER
        + "1700000000.500000\tCabc\t10.0.0.1\t2001:DB8:0:0::1\t443\ttcp\t-\t-\t900\tSF\tT"
        + "\t(empty)\n"
        + "#close\t2023-11-15-01-00-00\n",
    )
    (rec,) = list(iter_file(path))
    assert rec["ts"] == 1_700_000_000.5
    assert rec["id.resp_h"] == "2001:db8::1"  # compressed, lower-case
    assert rec["id.resp_p"] == 443
    assert rec["service"] is None  # '-' → None
    assert rec["duration"] is None
    assert rec["orig_bytes"] == 900
    assert rec["local_orig"] is True
    assert rec["tunnel_parents"] == []  # (empty) container


def test_tsv_truncated_and_malformed_lines_are_skipped(tmp_path: Path) -> None:
    path = write(
        tmp_path / "conn.log",
        TSV_HEADER
        + "1700000000.0\tCa\t10.0.0.1\t10.0.0.2\t445\ttcp\tsmb\t1.0\t10\tSF\tT\t-\n"
        + "1700000001.0\tCb\t10.0.0.1\t10.0.0.2\t44\n"  # truncated mid-write
        + "notatime\tCc\t10.0.0.1\t10.0.0.2\t445\ttcp\tsmb\t1.0\t10\tSF\tT\t-\n",
    )
    stats = ReadStats()
    records = list(iter_file(path, stats))
    assert [r["uid"] for r in records] == ["Ca"]
    assert stats.malformed == 2


def test_tsv_escapes_decode_like_zeek() -> None:
    # Zeek writes the UNC path \\host\ADMIN$ as \\\\host\\ADMIN$ in TSV.
    assert unescape_zeek("\\\\\\\\10.1.5.20\\\\ADMIN$") == "\\\\10.1.5.20\\ADMIN$"
    assert unescape_zeek("a\\x09b") == "a\tb"
    assert unescape_zeek("plain") == "plain"


def test_json_logs_flatten_and_normalize(tmp_path: Path) -> None:
    lines = [
        {"ts": 1700000000.25, "uid": "C1", "id.orig_h": "10.0.0.1", "id.resp_h": "FD00::0:1"},
        {"ts": "2023-11-14T22:13:21.000000Z", "uid": "C2", "id": {"orig_h": "10.0.0.2"}},
        "not-an-object",
    ]
    path = write(tmp_path / "conn.log", "\n".join(json.dumps(x) for x in lines) + "\n{trunc")
    stats = ReadStats()
    records = list(iter_file(path, stats))
    assert records[0]["id.resp_h"] == "fd00::1"
    assert records[1]["id.orig_h"] == "10.0.0.2"  # nested object flattened
    assert records[1]["ts"] == pytest.approx(1_700_000_001.0)  # ISO8601 timestamps accepted
    assert "id.resp_p" not in records[0]  # missing key → absent → .get() is None
    assert stats.malformed == 2


def test_reader_sorts_dedupes_and_filters(tmp_path: Path) -> None:
    rows = [
        "1700000005.0\tCdup\t10.0.0.1\t10.0.0.2\t445\ttcp\t-\t1.0\t10\tSF\tT\t-",
        "1700000001.0\tCfirst\t10.0.0.1\t10.0.0.2\t445\ttcp\t-\t1.0\t10\tSF\tT\t-",
        "1700000005.0\tCdup\t10.0.0.1\t10.0.0.2\t445\ttcp\t-\t1.0\t10\tSF\tT\t-",
        "1700009999.0\tClate\t10.0.0.1\t10.0.0.2\t445\ttcp\t-\t1.0\t10\tSF\tT\t-",
    ]
    write(tmp_path / "conn.log", TSV_HEADER + "\n".join(rows) + "\n")
    reader = ZeekLogReader()
    records = reader.read(tmp_path, "conn", start=1_700_000_000, end=1_700_000_100)
    assert [r["uid"] for r in records] == ["Cfirst", "Cdup"]
    assert reader.stats["conn"].duplicates == 1


def test_gzip_and_rotated_discovery(tmp_path: Path) -> None:
    sub = tmp_path / "sensor-a"
    sub.mkdir()
    body = TSV_HEADER + "1700000000.0\tCg\t10.0.0.1\t10.0.0.2\t445\ttcp\t-\t1.0\t10\tSF\tT\t-\n"
    with gzip.open(sub / "conn.2023-11-15-00-00-00.log.gz", "wt", encoding="utf-8") as fh:
        fh.write(body)
    write(tmp_path / "conn.log", body.replace("Cg", "Ch"))
    write(tmp_path / "conn_summary.log", body)  # different log type: must be ignored
    found = discover_logs(tmp_path, "conn")
    assert [p.name for p in found] == ["conn.log", "conn.2023-11-15-00-00-00.log.gz"]
    uids = [r["uid"] for r in ZeekLogReader().read(tmp_path, "conn")]
    assert sorted(uids) == ["Cg", "Ch"]
    assert scan_time_bounds(tmp_path, ["conn"]) == (1_700_000_000.0, 1_700_000_000.0)


def test_dns_queries_normalized_and_arpa_dropped(tmp_path: Path) -> None:
    rows = [
        {"ts": 1.0, "uid": "D1", "query": "WWW.Example.COM."},
        {"ts": 2.0, "uid": "D2", "query": "1.0.0.10.in-addr.arpa"},
        {"ts": 3.0, "uid": "D3", "query": "b.a.8.ip6.arpa"},
    ]
    write(tmp_path / "dns.log", "\n".join(json.dumps(r) for r in rows) + "\n")
    reader = ZeekLogReader()
    records = reader.read(tmp_path, "dns")
    assert [r["query"] for r in records] == ["www.example.com"]
    assert reader.stats["dns"].dropped == 2
    kept = ZeekLogReader(drop_arpa=False).read(tmp_path, "dns")
    assert len(kept) == 3


def test_real_zeek_header_fixture_parses() -> None:
    from tests.conftest import FIXTURES

    records = ZeekLogReader().read(FIXTURES / "lateral_movement", "conn")
    assert records and all(isinstance(r["ts"], float) for r in records)
    assert {"ip_proto", "history", "id.orig_p"} <= records[0].keys()
