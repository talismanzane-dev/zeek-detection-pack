#!/usr/bin/env python3
"""Generate the Docker-lab demo pcap (``make lab-demo``).

The capture is synthetic and deterministic (seeded) and mirrors the labeled
fixtures, so Zeek → zdp yields detections within one ``docker compose up``:

* a 60 s ±5 % HTTPS-port beacon (c2_beaconing),
* an iodine-style TXT tunnel with base32 subdomains (dns_tunneling),
* a 40-name NXDOMAIN burst of random domains (dga),
* an SMB2 tree connect to ``ADMIN$`` plus ``PSEXESVC.exe`` create/write
  (lateral_movement, admin-share signal),
* light benign web and DNS traffic.

Only the Python standard library is used. Packets carry valid IPv4/TCP/UDP
checksums, so Zeek does not need ``-C``.

Usage::

    python tools/gen_demo_pcap.py --out pcaps/zdp-demo.pcap
"""

from __future__ import annotations

import argparse
import base64
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

BASE_TS = 1_700_000_000.0  # 2023-11-14T22:13:20Z
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")

ACK, PSH, SYN, FIN = 0x10, 0x08, 0x02, 0x01


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip4(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


class PcapWriter:
    def __init__(self) -> None:
        self.packets: list[tuple[float, bytes]] = []
        self._ip_id = 1

    def ipv4(self, ts: float, src: str, dst: str, proto: int, payload: bytes) -> None:
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            self._ip_id,
            0x4000,
            64,
            proto,
            0,
            _ip4(src),
            _ip4(dst),
        )
        header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
        frame = SERVER_MAC + CLIENT_MAC + b"\x08\x00" + header + payload
        self.packets.append((ts, frame))

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, frame in sorted(self.packets, key=lambda p: p[0]):
                sec = int(ts)
                usec = round((ts - sec) * 1_000_000)
                if usec >= 1_000_000:
                    sec, usec = sec + 1, usec - 1_000_000
                fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                fh.write(frame)


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return _ip4(src) + _ip4(dst) + struct.pack("!BBH", 0, proto, length)


def udp(w: PcapWriter, ts: float, src: str, sport: int, dst: str, dport: int, data: bytes) -> None:
    length = 8 + len(data)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    csum = _checksum(_pseudo(src, dst, 17, length) + header + data) or 0xFFFF
    w.ipv4(ts, src, dst, 17, header[:6] + struct.pack("!H", csum) + data)


@dataclass
class TCPSession:
    w: PcapWriter
    client: str
    cport: int
    server: str
    sport: int
    rng: random.Random
    cseq: int = field(init=False)
    sseq: int = field(init=False)

    def __post_init__(self) -> None:
        self.cseq = self.rng.randrange(1, 2**31)
        self.sseq = self.rng.randrange(1, 2**31)

    def _seg(self, ts: float, from_client: bool, flags: int, data: bytes = b"") -> None:
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        seq, ack = (self.cseq, self.sseq) if from_client else (self.sseq, self.cseq)
        header = struct.pack(
            "!HHIIBBHHH", sp, dp, seq, ack if flags & ACK else 0, 5 << 4, flags, 65535, 0, 0
        )
        csum = _checksum(_pseudo(src, dst, 6, len(header) + len(data)) + header + data)
        header = header[:16] + struct.pack("!H", csum) + header[18:]
        self.w.ipv4(ts, src, dst, 6, header + data)
        advance = len(data) + (1 if flags & (SYN | FIN) else 0)
        if from_client:
            self.cseq = (self.cseq + advance) % 2**32
        else:
            self.sseq = (self.sseq + advance) % 2**32

    def open(self, ts: float) -> float:
        self._seg(ts, True, SYN)
        self._seg(ts + 0.010, False, SYN | ACK)
        self._seg(ts + 0.011, True, ACK)
        return ts + 0.012

    def send(self, ts: float, from_client: bool, data: bytes) -> float:
        for i in range(0, len(data), 1400):
            self._seg(ts, from_client, PSH | ACK, data[i : i + 1400])
            ts += 0.0005
        self._seg(ts + 0.005, not from_client, ACK)
        return ts + 0.006

    def close(self, ts: float) -> float:
        self._seg(ts, True, FIN | ACK)
        self._seg(ts + 0.005, False, FIN | ACK)
        self._seg(ts + 0.006, True, ACK)
        return ts + 0.007


# --- DNS ----------------------------------------------------------------------


def _qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def dns_exchange(
    w: PcapWriter,
    ts: float,
    client: str,
    resolver: str,
    txid: int,
    name: str,
    qtype: int,
    rcode: int = 0,
    answers: list[bytes] | None = None,
) -> None:
    sport = 30000 + txid % 30000
    question = _qname(name) + struct.pack("!HH", qtype, 1)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    udp(w, ts, client, sport, resolver, 53, query)
    answers = answers or []
    flags = 0x8180 | (rcode & 0xF)
    body = struct.pack("!HHHHHH", txid, flags, 1, len(answers), 0, 0) + question
    for rdata in answers:
        body += struct.pack("!HHHIH", 0xC00C, qtype, 1, 60, len(rdata)) + rdata
    udp(w, ts + 0.02, resolver, 53, client, sport, body)


def txt_rdata(text: bytes) -> bytes:
    out = b""
    for i in range(0, len(text), 255):
        chunk = text[i : i + 255]
        out += bytes([len(chunk)]) + chunk
    return out


# --- SMB2 ---------------------------------------------------------------------


def _smb2(
    command: int, mid: int, tree_id: int, body: bytes, response: bool, status: int = 0
) -> bytes:
    flags = 0x00000001 if response else 0
    header = struct.pack(
        "<4sHHIHHIIQIIQ16s",
        b"\xfeSMB",
        64,
        1,
        status,
        command,
        1,
        flags,
        0,
        mid,
        0xFEFF,
        tree_id,
        0x0000400000000011,
        b"\0" * 16,
    )
    msg = header + body
    return struct.pack(">I", len(msg)) + msg


def smb_admin_share_psexec(
    w: PcapWriter,
    ts: float,
    client: str,
    server: str,
    rng: random.Random,
    share: str,
    filename: str,
    payload: bytes,
) -> None:
    s = TCPSession(w, client, 49_700 + rng.randrange(200), server, 445, rng)
    t = s.open(ts)
    path = f"\\\\{server}\\{share}".encode("utf-16-le")
    # TREE_CONNECT request (StructureSize 9) / response (16)
    t = s.send(t, True, _smb2(3, 2, 0, struct.pack("<HHHH", 9, 0, 72, len(path)) + path, False))
    t = s.send(t, False, _smb2(3, 2, 1, struct.pack("<HBBIII", 16, 1, 0, 0, 0, 0x001F01FF), True))
    # CREATE request (57) / response (89)
    name = filename.encode("utf-16-le")
    create_req = (
        struct.pack(
            "<HBBIQQIIIIIHHII",
            57,
            0,
            0,
            2,
            0,
            0,
            0x0012019F,
            0x80,
            0x7,
            2,
            0x40,
            120,
            len(name),
            0,
            0,
        )
        + name
    )
    t = s.send(t, True, _smb2(5, 3, 1, create_req, False))
    file_id = struct.pack("<QQ", 0x1D, 0x9000_0001)
    filetime = 133_445_000_000_000_000
    create_resp = struct.pack(
        "<HBBIQQQQQQII16sII",
        89,
        0,
        0,
        2,
        filetime,
        filetime,
        filetime,
        filetime,
        0,
        len(payload),
        0x80,
        0,
        file_id,
        0,
        0,
    )
    t = s.send(t, False, _smb2(5, 3, 1, create_resp, True))
    # WRITE request (49) / response (17)
    write_req = (
        struct.pack("<HHIQ16sIIHHI", 49, 112, len(payload), 0, file_id, 0, 0, 0, 0, 0) + payload
    )
    t = s.send(t, True, _smb2(9, 4, 1, write_req, False))
    t = s.send(t, False, _smb2(9, 4, 1, struct.pack("<HHIIHH", 17, 0, len(payload), 0, 0, 0), True))
    # CLOSE request (24) / response (60)
    t = s.send(t, True, _smb2(6, 5, 1, struct.pack("<HHI16s", 24, 0, 0, file_id), False))
    close_resp = struct.pack("<HHIQQQQQQI", 60, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    t = s.send(t, False, _smb2(6, 5, 1, close_resp, True))
    s.close(t + 0.05)


# --- scenario -----------------------------------------------------------------


def build(seed: int) -> PcapWriter:
    rng = random.Random(seed)
    w = PcapWriter()
    resolver = "10.1.0.53"

    # Benign web sessions from a few workstations (Poisson arrivals).
    for host in ("10.1.2.21", "10.1.2.22", "10.1.2.23"):
        t = BASE_TS + rng.uniform(0, 60)
        while t < BASE_TS + 3600:
            dst = rng.choice(["198.51.100.10", "198.51.100.20", "198.51.100.30"])
            s = TCPSession(w, host, rng.randrange(49152, 65535), dst, 443, rng)
            u = s.open(t)
            u = s.send(u, True, rng.randbytes(rng.randrange(300, 1500)))
            u = s.send(u + 0.05, False, rng.randbytes(rng.randrange(2_000, 40_000)))
            s.close(u + 0.1)
            t += rng.expovariate(1 / 90)

    # C2 beacon: 60 s ± 5 % jitter, ~900 B requests, small responses.
    t = BASE_TS + 30
    for _ in range(70):
        s = TCPSession(w, "10.1.2.15", rng.randrange(49152, 65535), "203.0.113.40", 443, rng)
        u = s.open(t)
        u = s.send(u, True, rng.randbytes(880 + rng.randrange(40)))
        u = s.send(u + 0.04, False, rng.randbytes(180 + rng.randrange(60)))
        s.close(u + 0.02)
        t += 60 * (1 + rng.uniform(-0.05, 0.05))

    # Benign DNS.
    txid = 1
    for _ in range(150):
        name = rng.choice(
            [
                "www.google.com",
                "outlook.office365.com",
                "login.microsoftonline.com",
                "www.wikipedia.org",
                "github.com",
            ]
        )
        dns_exchange(
            w,
            BASE_TS + rng.uniform(0, 3600),
            rng.choice(["10.1.2.21", "10.1.2.22"]),
            resolver,
            txid,
            name,
            1,
            answers=[bytes([198, 51, 100, rng.randrange(1, 254)])],
        )
        txid += 1

    # iodine-style TXT tunnel: base32 payload labels under t.example.net.
    t = BASE_TS + 600
    for _ in range(150):
        payload = base64.b32encode(rng.randbytes(60)).decode().rstrip("=").lower()
        name = f"{payload[:48]}.{payload[48:]}.t.example.net"
        answer = base64.b32encode(rng.randbytes(90)).rstrip(b"=").lower()
        dns_exchange(w, t, "10.1.3.22", resolver, txid, name, 16, answers=[txt_rdata(answer)])
        txid += 1
        t += rng.uniform(4, 10)

    # DGA: 40 random-name NXDOMAIN lookups in ~4 minutes.
    t = BASE_TS + 1800
    letters = "abcdefghijklmnopqrstuvwxyz"
    for _ in range(40):
        sld = "".join(rng.choice(letters) for _ in range(rng.randrange(11, 17)))
        dns_exchange(
            w,
            t,
            "10.1.4.31",
            resolver,
            txid,
            f"{sld}.{rng.choice(['com', 'net', 'org'])}",
            1,
            rcode=3,
        )
        txid += 1
        t += rng.uniform(3, 9)

    # PsExec-style staging: ADMIN$ tree connect + PSEXESVC.exe create/write.
    smb_admin_share_psexec(
        w,
        BASE_TS + 2400,
        "10.1.2.15",
        "10.1.5.20",
        rng,
        "ADMIN$",
        "PSEXESVC.exe",
        b"MZ" + rng.randbytes(4094),
    )
    return w


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("pcaps/zdp-demo.pcap"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)
    writer = build(args.seed)
    writer.write(args.out)
    print(f"wrote {len(writer.packets)} packets to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
