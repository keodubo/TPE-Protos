#!/usr/bin/env python3
"""Origin TCP server used by the SOCKS5 stress harness."""

from __future__ import annotations

import argparse
import asyncio
import signal
import struct
import sys


def payload_bytes(size: int) -> bytes:
    return bytes((i % 251 for i in range(size)))


async def handle_client(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter,
                        payload: bytes,
                        chunk_size: int,
                        delay_ms: int) -> None:
    try:
        try:
            request = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
            requested = struct.unpack("!I", request)[0]
        except asyncio.TimeoutError:
            requested = len(payload)
        except asyncio.IncompleteReadError:
            requested = len(payload)
        response = payload[:min(requested, len(payload))]
        for offset in range(0, len(response), chunk_size):
            writer.write(response[offset:offset + chunk_size])
            await writer.drain()
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def main_async(args: argparse.Namespace) -> int:
    payload = payload_bytes(args.payload_bytes)
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, payload, args.chunk_size, args.delay_ms),
        args.host,
        args.port,
    )
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"origin listening on {sockets}", flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    async with server:
        await stop.wait()
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, default=65536)
    parser.add_argument("--chunk-size", type=int, default=16384)
    parser.add_argument("--delay-ms", type=int, default=0)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
