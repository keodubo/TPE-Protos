#!/usr/bin/env python3
"""Generate stress charts from the CSV files produced by run_stress.py."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


SUMMARY_NAME = "2026-07-05_socks5-stress-summary_v1.csv"
SHUTDOWN_NAME = "2026-07-05_socks5-shutdown_v1.csv"


def load_summary(in_dir: Path) -> list[dict[str, str]]:
    path = in_dir / SUMMARY_NAME
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def grouped(rows: list[dict[str, str]], payload: int | None = None) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    if payload is None and rows:
        payload = max(int(row["payload_bytes"]) for row in rows)
    for row in rows:
        if int(row["payload_bytes"]) == payload:
            groups[row["target_mode"]].append(row)
    for values in groups.values():
        values.sort(key=lambda r: int(r["concurrency"]))
    return groups


def save_all(fig, in_dir: Path, stem: str, formats: list[str]) -> None:
    for fmt in formats:
        fig.savefig(in_dir / f"{stem}.{fmt}", bbox_inches="tight", dpi=150)
    plt.close(fig)


def plot_throughput(rows: list[dict[str, str]], in_dir: Path, formats: list[str]) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    for mode, values in grouped(rows).items():
        ax.plot([int(r["concurrency"]) for r in values],
                [float(r["throughput_MiBps"]) for r in values],
                marker="o", label=mode)
    ax.set_title("Throughput agregado vs concurrencia")
    ax.set_xlabel("Conexiones concurrentes")
    ax.set_ylabel("MiB/s")
    ax.grid(True, alpha=0.3)
    ax.legend()
    save_all(fig, in_dir, "2026-07-05_fig-throughput-vs-concurrency_v1", formats)


def plot_errors(rows: list[dict[str, str]], in_dir: Path, formats: list[str]) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    for mode, values in grouped(rows).items():
        attempted = [max(int(r["attempted"]), 1) for r in values]
        failed = [int(r["conn_failed"]) for r in values]
        ax.plot([int(r["concurrency"]) for r in values],
                [100.0 * f / a for f, a in zip(failed, attempted)],
                marker="o", label=mode)
    ax.set_title("Tasa de error vs concurrencia")
    ax.set_xlabel("Conexiones concurrentes")
    ax.set_ylabel("Error (%)")
    ax.grid(True, alpha=0.3)
    ax.legend()
    save_all(fig, in_dir, "2026-07-05_fig-error-rate-vs-concurrency_v1", formats)


def plot_latency(rows: list[dict[str, str]], in_dir: Path, formats: list[str]) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    for mode, values in grouped(rows).items():
        xs = [int(r["concurrency"]) for r in values]
        ax.plot(xs, [float(r["p50_total_ms"]) for r in values],
                marker="o", label=f"{mode} p50")
        ax.plot(xs, [float(r["p95_total_ms"]) for r in values],
                marker="s", linestyle="--", label=f"{mode} p95")
    ax.set_title("Latencia total p50/p95 vs concurrencia")
    ax.set_xlabel("Conexiones concurrentes")
    ax.set_ylabel("ms")
    ax.grid(True, alpha=0.3)
    ax.legend()
    save_all(fig, in_dir, "2026-07-05_fig-latency-p50-p95-vs-concurrency_v1", formats)


def plot_shutdown(in_dir: Path, formats: list[str]) -> None:
    path = in_dir / SHUTDOWN_NAME
    if not path.exists():
        return
    with path.open(newline="", encoding="utf-8") as f:
        rows = []
        for row in csv.DictReader(f):
            try:
                float(row.get("shutdown_wall_s", ""))
            except ValueError:
                continue
            rows.append(row)
    if not rows:
        return
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar([row["signal_count"] for row in rows],
           [float(row["shutdown_wall_s"]) for row in rows])
    ax.set_title("Tiempo de apagado bajo carga")
    ax.set_xlabel("Señales")
    ax.set_ylabel("s")
    ax.grid(True, axis="y", alpha=0.3)
    save_all(fig, in_dir, "2026-07-05_fig-shutdown-drain-time_v1", formats)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in-dir", required=True)
    parser.add_argument("--formats", default="png,svg")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    in_dir = Path(args.in_dir)
    formats = [fmt for fmt in args.formats.split(",") if fmt]
    rows = load_summary(in_dir)
    if not rows:
        raise SystemExit("summary CSV has no rows")
    plot_throughput(rows, in_dir, formats)
    plot_errors(rows, in_dir, formats)
    plot_latency(rows, in_dir, formats)
    plot_shutdown(in_dir, formats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
