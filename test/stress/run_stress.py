#!/usr/bin/env python3
"""Run reproducible SOCKS5 stress sweeps and write CSV evidence."""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import platform
import resource
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import stress_socks5


SUMMARY_NAME = "2026-07-05_socks5-stress-summary_v1.csv"
CONNECTIONS_NAME = "2026-07-05_socks5-stress-connections_v1.csv"
SHUTDOWN_NAME = "2026-07-05_socks5-shutdown_v1.csv"


def parse_csv_ints(raw: str) -> list[int]:
    return [int(item) for item in raw.split(",") if item]


def parse_csv_strs(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def wait_port(port: int, deadline_s: float, proc: subprocess.Popen | None,
              log_path: Path) -> None:
    deadline = time.monotonic() + deadline_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            raise RuntimeError(f"process exited before port {port} was ready; see {log_path}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError as exc:
            last = exc
            time.sleep(0.05)
    raise RuntimeError(f"port {port} not ready: {last!r}; see {log_path}")


def stop_proc(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def read_metrics(port: int, admin: str) -> dict[str, int]:
    user, password = admin.split(":", 1)
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(f"HELLO 1\r\nAUTH {user} {password}\r\nMETRICS\r\n".encode("ascii"))
        data = b""
        while data.count(b"\r\n") < 3:
            data += sock.recv(4096)
        lines = data.split(b"\r\n")
        count = int(lines[2].split()[1])
        while len([line for line in lines[3:] if line]) < count:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            lines = data.split(b"\r\n")
    metrics: dict[str, int] = {}
    for line in lines[3:3 + count]:
        if not line:
            continue
        key, value = line.decode("ascii").split(" ", 1)
        metrics[key] = int(value)
    return metrics


def fd_setsize() -> str:
    code = "#include <sys/select.h>\n#include <stdio.h>\nint main(){printf(\"%d\\n\", FD_SETSIZE);}\n"
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "fdset.c"
            out = Path(td) / "fdset"
            src.write_text(code, encoding="utf-8")
            subprocess.run(["cc", str(src), "-o", str(out)], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return subprocess.check_output([str(out)], text=True).strip()
    except Exception:
        return "unknown"


def run_id_from_out(out_dir: Path) -> str:
    return out_dir.name


def static_env() -> dict[str, str]:
    try:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        ulimit_n = str(soft)
    except Exception:
        ulimit_n = "unknown"
    try:
        open_max = str(os.sysconf("SC_OPEN_MAX"))
    except Exception:
        open_max = "unknown"
    return {
        "host": socket.gethostname(),
        "os": platform.platform(),
        "fd_setsize": fd_setsize(),
        "ulimit_n": ulimit_n,
        "open_max": open_max,
    }


def append_shutdown_row(path: Path,
                        row: dict[str, object],
                        write_header: bool,
                        append: bool = True) -> None:
    fields = [
        "run_id", "concurrency", "payload_bytes", "signal_count",
        "active_before_signal", "new_conn_after_signal", "connections_completed",
        "connections_aborted", "server_exited", "server_exit_code",
        "shutdown_wall_s", "forced_wall_s", "first_error",
    ]
    mode = "a" if append else "w"
    with path.open(mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


async def shutdown_probe(args: argparse.Namespace,
                         run_id: str,
                         server_proc: subprocess.Popen,
                         origin_proc: subprocess.Popen,
                         origin_log,
                         out_dir: Path) -> None:
    stop_proc(origin_proc)
    origin_proc = subprocess.Popen([
        sys.executable, "test/stress/origin_server.py",
        "--port", str(args.origin_port),
        "--payload-bytes", str(args.shutdown_payload_bytes),
        "--delay-ms", str(args.shutdown_origin_delay_ms),
    ], stdout=origin_log, stderr=subprocess.STDOUT, text=True)
    wait_port(args.origin_port, 3.0, origin_proc, out_dir / "origin.log")

    case_id = "shutdown-sigterm"
    task = asyncio.create_task(stress_socks5.run_case(
        run_id, case_id, "127.0.0.1", args.socks_port, args.user, args.password,
        "ipv4", "127.0.0.1", args.origin_port, args.shutdown_concurrency,
        args.shutdown_payload_bytes, args.timeout_s))
    await asyncio.sleep(0.25)
    try:
        active_before = read_metrics(args.mgmt_port, args.admin).get("concurrent-connections", 0)
    except Exception:
        active_before = -1

    started = time.perf_counter()
    os.kill(server_proc.pid, signal.SIGTERM)
    await asyncio.sleep(0.25)
    try:
        with socket.create_connection(("127.0.0.1", args.socks_port), timeout=0.5):
            new_conn_after = 1
    except OSError:
        new_conn_after = 0

    first_error = ""
    try:
        summary, rows = await task
        completed = int(summary["conn_ok"])
        aborted = int(summary["conn_failed"])
        first_error = str(summary["first_error"])
    except Exception as exc:
        completed = 0
        aborted = args.shutdown_concurrency
        first_error = repr(exc)

    try:
        server_proc.wait(timeout=max(args.timeout_s, 5.0))
        server_exited = 1
    except subprocess.TimeoutExpired:
        server_exited = 0
    shutdown_wall = time.perf_counter() - started
    append_shutdown_row(out_dir / SHUTDOWN_NAME, {
        "run_id": run_id,
        "concurrency": args.shutdown_concurrency,
        "payload_bytes": args.shutdown_payload_bytes,
        "signal_count": 1,
        "active_before_signal": active_before,
        "new_conn_after_signal": new_conn_after,
        "connections_completed": completed,
        "connections_aborted": aborted,
        "server_exited": server_exited,
        "server_exit_code": server_proc.poll(),
        "shutdown_wall_s": f"{shutdown_wall:.6f}",
        "forced_wall_s": "",
        "first_error": first_error,
    }, write_header=not (out_dir / SHUTDOWN_NAME).exists())
    stop_proc(origin_proc)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--server", default="./bin/server")
    parser.add_argument("--socks-port", type=int, default=11080)
    parser.add_argument("--mgmt-port", type=int, default=12080)
    parser.add_argument("--origin-port", type=int, default=18080)
    parser.add_argument("--user", default="user")
    parser.add_argument("--password", default="pass")
    parser.add_argument("--admin", default="root:toor")
    parser.add_argument("--concurrency", default="10,50")
    parser.add_argument("--payload-bytes", default="1024,65536")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--target-modes", default="ipv4")
    parser.add_argument("--timeout-s", type=float, default=10.0)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-shutdown", action="store_true")
    parser.add_argument("--shutdown-concurrency", type=int, default=50)
    parser.add_argument("--shutdown-payload-bytes", type=int, default=1048576)
    parser.add_argument("--shutdown-origin-delay-ms", type=int, default=5)
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = run_id_from_out(out_dir)
    run_log = (out_dir / "run.log").open("w", encoding="utf-8")
    server_log = (out_dir / "server.log").open("w", encoding="utf-8")
    origin_log = (out_dir / "origin.log").open("w", encoding="utf-8")

    origin_proc: subprocess.Popen | None = None
    server_proc: subprocess.Popen | None = None
    try:
        if not args.skip_build:
            subprocess.run(["make", "server", "client"], check=True)

        env = static_env()
        env_text = "\n".join(
            [f"timestamp_utc={datetime.now(timezone.utc).isoformat()}"]
            + [f"{key}={value}" for key, value in env.items()]
        ) + "\n"
        (out_dir / "env.txt").write_text(env_text, encoding="utf-8")

        origin_proc = subprocess.Popen([
            sys.executable, "test/stress/origin_server.py",
            "--port", str(args.origin_port),
            "--payload-bytes", str(max(parse_csv_ints(args.payload_bytes)
                                        + [args.shutdown_payload_bytes])),
        ], stdout=origin_log, stderr=subprocess.STDOUT, text=True)
        wait_port(args.origin_port, 3.0, origin_proc, out_dir / "origin.log")

        admin_user, admin_pass = args.admin.split(":", 1)
        server_proc = subprocess.Popen([
            args.server,
            "-p", str(args.socks_port),
            "-P", str(args.mgmt_port),
            "--admin", f"{admin_user}:{admin_pass}",
            "-u", f"{args.user}:{args.password}",
        ], stdout=server_log, stderr=subprocess.STDOUT, text=True)
        wait_port(args.socks_port, 3.0, server_proc, out_dir / "server.log")
        wait_port(args.mgmt_port, 3.0, server_proc, out_dir / "server.log")

        summary_path = out_dir / SUMMARY_NAME
        conn_path = out_dir / CONNECTIONS_NAME
        summary_fields = [
            "run_id", "timestamp_utc", "host", "os", "fd_setsize", "ulimit_n",
            "open_max", "target_mode", "concurrency", "payload_bytes", "repeat",
            "attempted", "conn_ok", "conn_failed", "total_bytes", "wall_time_s",
            "throughput_Bps", "throughput_MiBps", "conn_rate_s",
            "p50_socks_ms", "p95_socks_ms", "p50_total_ms", "p95_total_ms",
            "rep_nonzero", "first_error", "metrics_historic_delta",
            "metrics_failed_delta", "metrics_bytes_delta",
        ]
        conn_fields = list(stress_socks5.ConnectionResult.__dataclass_fields__.keys())

        with summary_path.open("w", newline="", encoding="utf-8") as sf, \
                conn_path.open("w", newline="", encoding="utf-8") as cf:
            sw = csv.DictWriter(sf, fieldnames=summary_fields)
            cw = csv.DictWriter(cf, fieldnames=conn_fields)
            sw.writeheader()
            cw.writeheader()
            for target_mode in parse_csv_strs(args.target_modes):
                target_host = "127.0.0.1" if target_mode == "ipv4" else "localhost"
                for payload in parse_csv_ints(args.payload_bytes):
                    for concurrency in parse_csv_ints(args.concurrency):
                        for repeat in range(1, args.repeats + 1):
                            case_id = f"{target_mode}-c{concurrency}-p{payload}-r{repeat}"
                            before = read_metrics(args.mgmt_port, args.admin)
                            summary, rows = asyncio.run(stress_socks5.run_case(
                                run_id, case_id, "127.0.0.1", args.socks_port,
                                args.user, args.password, target_mode, target_host,
                                args.origin_port, concurrency, payload, args.timeout_s))
                            after = read_metrics(args.mgmt_port, args.admin)
                            row = {
                                "run_id": run_id,
                                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                                "host": env["host"],
                                "os": env["os"],
                                "fd_setsize": env["fd_setsize"],
                                "ulimit_n": env["ulimit_n"],
                                "open_max": env["open_max"],
                                "target_mode": target_mode,
                                "concurrency": concurrency,
                                "payload_bytes": payload,
                                "repeat": repeat,
                                **summary,
                                "metrics_historic_delta":
                                    after.get("historic-connections", 0)
                                    - before.get("historic-connections", 0),
                                "metrics_failed_delta":
                                    after.get("failed-connections", 0)
                                    - before.get("failed-connections", 0),
                                "metrics_bytes_delta":
                                    after.get("bytes-transferred", 0)
                                    - before.get("bytes-transferred", 0),
                            }
                            sw.writerow(row)
                            sf.flush()
                            for result in rows:
                                cw.writerow(stress_socks5.asdict(result))
                            cf.flush()
                            print(f"{case_id}: ok={summary['conn_ok']} "
                                  f"fail={summary['conn_failed']} "
                                  f"throughput={summary['throughput_MiBps']} MiB/s",
                                  file=run_log, flush=True)
        if args.skip_shutdown:
            append_shutdown_row(out_dir / SHUTDOWN_NAME, {
                "run_id": run_id,
                "concurrency": args.shutdown_concurrency,
                "payload_bytes": args.shutdown_payload_bytes,
                "signal_count": 0,
                "active_before_signal": "",
                "new_conn_after_signal": "",
                "connections_completed": "",
                "connections_aborted": "",
                "server_exited": "",
                "server_exit_code": "",
                "shutdown_wall_s": "",
                "forced_wall_s": "",
                "first_error": "skipped",
            }, write_header=True, append=False)
        else:
            asyncio.run(shutdown_probe(args, run_id, server_proc, origin_proc,
                                       origin_log, out_dir))
            origin_proc = None
            server_proc = None
        return 0
    finally:
        stop_proc(server_proc)
        stop_proc(origin_proc)
        run_log.close()
        server_log.close()
        origin_log.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
