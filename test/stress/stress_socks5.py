#!/usr/bin/env python3
"""Concurrent SOCKS5 stress client used by run_stress.py and standalone runs."""

from __future__ import annotations

import argparse
import asyncio
import csv
import statistics
import struct
import sys
import time
from dataclasses import dataclass, asdict


HELLO = b"\x05\x01\x02"


@dataclass
class ConnectionResult:
    run_id: str
    case_id: str
    conn_id: int
    target_mode: str
    concurrency: int
    payload_bytes: int
    ok: int
    error_stage: str
    error: str
    rep: int
    tcp_ms: float
    socks_ms: float
    ttfb_ms: float
    total_ms: float
    bytes_up: int
    bytes_down: int


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * pct))
    return ordered[idx]


def auth_message(user: str, password: str) -> bytes:
    ub = user.encode("ascii")
    pb = password.encode("ascii")
    if len(ub) > 255 or len(pb) > 255:
        raise ValueError("SOCKS5 auth fields must fit in one byte")
    return b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb


def request_message(mode: str, host: str, port: int) -> bytes:
    if mode == "ipv4":
        addr = bytes(int(part) for part in host.split("."))
        atyp = b"\x01"
        body = addr
    elif mode == "fqdn":
        name = host.encode("ascii")
        if len(name) > 255:
            raise ValueError("FQDN too long for SOCKS5")
        atyp = b"\x03"
        body = bytes([len(name)]) + name
    else:
        raise ValueError(f"unsupported target mode {mode}")
    return b"\x05\x01\x00" + atyp + body + struct.pack("!H", port)


async def read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def one_connection(conn_id: int,
                         run_id: str,
                         case_id: str,
                         proxy_host: str,
                         proxy_port: int,
                         user: str,
                         password: str,
                         target_mode: str,
                         target_host: str,
                         target_port: int,
                         payload_bytes: int,
                         timeout_s: float) -> ConnectionResult:
    started = time.perf_counter()
    tcp_ms = socks_ms = ttfb_ms = total_ms = 0.0
    bytes_down = 0
    rep = -1
    stage = "tcp"
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=timeout_s)
        tcp_done = time.perf_counter()
        tcp_ms = (tcp_done - started) * 1000.0

        stage = "hello"
        writer.write(HELLO)
        await writer.drain()
        method = await asyncio.wait_for(read_exact(reader, 2), timeout=timeout_s)
        if method != b"\x05\x02":
            raise RuntimeError(f"method={method.hex()}")

        stage = "auth"
        writer.write(auth_message(user, password))
        await writer.drain()
        auth = await asyncio.wait_for(read_exact(reader, 2), timeout=timeout_s)
        if auth != b"\x01\x00":
            raise RuntimeError(f"auth={auth.hex()}")

        stage = "request"
        writer.write(request_message(target_mode, target_host, target_port))
        await writer.drain()
        reply = await asyncio.wait_for(read_exact(reader, 4), timeout=timeout_s)
        if reply[:3] != b"\x05\x00\x00":
            rep = reply[1] if len(reply) > 1 else -1
            raise RuntimeError(f"rep={rep}")
        rep = 0
        atyp = reply[3]
        if atyp == 0x01:
            await asyncio.wait_for(read_exact(reader, 6), timeout=timeout_s)
        elif atyp == 0x04:
            await asyncio.wait_for(read_exact(reader, 18), timeout=timeout_s)
        else:
            raise RuntimeError(f"reply_atyp={atyp}")
        socks_ms = (time.perf_counter() - started) * 1000.0

        stage = "transfer"
        request = struct.pack("!I", payload_bytes)
        writer.write(request)
        await writer.drain()
        first = True
        while bytes_down < payload_bytes:
            chunk = await asyncio.wait_for(
                reader.read(min(65536, payload_bytes - bytes_down)),
                timeout=timeout_s,
            )
            if not chunk:
                break
            if first:
                ttfb_ms = (time.perf_counter() - started) * 1000.0
                first = False
            bytes_down += len(chunk)
        total_ms = (time.perf_counter() - started) * 1000.0
        if bytes_down != payload_bytes:
            raise RuntimeError(f"bytes_down={bytes_down}")
        return ConnectionResult(run_id, case_id, conn_id, target_mode,
                                0, payload_bytes, 1, "", "", rep, tcp_ms,
                                socks_ms, ttfb_ms, total_ms, len(request), bytes_down)
    except Exception as exc:  # noqa: BLE001 - persisted as CSV evidence.
        total_ms = (time.perf_counter() - started) * 1000.0
        return ConnectionResult(run_id, case_id, conn_id, target_mode,
                                0, payload_bytes, 0, stage, repr(exc), rep,
                                tcp_ms, socks_ms, ttfb_ms, total_ms, 0, bytes_down)
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def run_case(run_id: str,
                   case_id: str,
                   proxy_host: str,
                   proxy_port: int,
                   user: str,
                   password: str,
                   target_mode: str,
                   target_host: str,
                   target_port: int,
                   concurrency: int,
                   payload_bytes: int,
                   timeout_s: float) -> tuple[dict[str, object], list[ConnectionResult]]:
    wall_start = time.perf_counter()
    results = await asyncio.gather(*[
        one_connection(i, run_id, case_id, proxy_host, proxy_port, user, password,
                       target_mode, target_host, target_port, payload_bytes, timeout_s)
        for i in range(concurrency)
    ])
    wall_time = time.perf_counter() - wall_start
    for result in results:
        result.concurrency = concurrency

    ok = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    total_bytes = sum(r.bytes_down for r in results)
    socks_lat = [r.socks_ms for r in ok]
    total_lat = [r.total_ms for r in ok]
    first_error = failed[0].error if failed else ""
    summary = {
        "attempted": concurrency,
        "conn_ok": len(ok),
        "conn_failed": len(failed),
        "total_bytes": total_bytes,
        "wall_time_s": f"{wall_time:.6f}",
        "throughput_Bps": f"{(total_bytes / wall_time) if wall_time else 0:.2f}",
        "throughput_MiBps": f"{(total_bytes / wall_time / 1048576) if wall_time else 0:.4f}",
        "conn_rate_s": f"{(len(ok) / wall_time) if wall_time else 0:.2f}",
        "p50_socks_ms": f"{percentile(socks_lat, 0.50):.3f}",
        "p95_socks_ms": f"{percentile(socks_lat, 0.95):.3f}",
        "p50_total_ms": f"{percentile(total_lat, 0.50):.3f}",
        "p95_total_ms": f"{percentile(total_lat, 0.95):.3f}",
        "rep_nonzero": sum(1 for r in results if r.rep not in (-1, 0)),
        "first_error": first_error,
    }
    return summary, results


def write_connections(path: str, rows: list[ConnectionResult]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="manual")
    parser.add_argument("--case-id", default="manual")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--user", default="user")
    parser.add_argument("--password", default="pass")
    parser.add_argument("--target-mode", choices=("ipv4", "fqdn"), default="ipv4")
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--payload-bytes", type=int, default=65536)
    parser.add_argument("--timeout-s", type=float, default=10.0)
    parser.add_argument("--connections-csv")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    summary, rows = asyncio.run(run_case(
        args.run_id, args.case_id, args.proxy_host, args.proxy_port,
        args.user, args.password, args.target_mode, args.target_host,
        args.target_port, args.concurrency, args.payload_bytes, args.timeout_s))
    for key, value in summary.items():
        print(f"{key}={value}")
    if args.connections_csv:
        write_connections(args.connections_csv, rows)
    return 0 if int(summary["conn_failed"]) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
