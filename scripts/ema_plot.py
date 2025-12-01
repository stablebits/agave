#!/usr/bin/env python3
"""
Plot EMA load and staked quotas from the Rust `ema_sim` CSV output.

Usage:
  cargo run -p solana-streamer --bin ema_sim -- <sequence> --stakes 0.01,0.001 --csv | \
    python3 scripts/ema_plot.py --stakes 0.01,0.001 --output plot.png

Input format: CSV rows with columns:
  step,load_in_5ms,ema,quota_<stake1>,quota_<stake2>,...
The Rust simulator prints a header row; this script auto-detects columns.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from typing import List, Dict, Sequence

import matplotlib.pyplot as plt  # type: ignore


@dataclass
class Sample:
    step: int
    load: int
    ema: int
    quotas: Dict[str, int]


def parse_csv(stdin: Sequence[str]) -> List[Sample]:
    reader = csv.reader(stdin)
    rows = list(reader)
    if not rows:
        raise SystemExit("No data on stdin")
    header = rows[1]
    samples: List[Sample] = []
    for r in rows[2:]:
        if len(r) < 3:
            continue
        try:
            step = int(r[0])
            load = int(r[1])
            ema = int(r[2])
        except ValueError:
            continue
        quotas: Dict[str, int] = {}
        for idx, col in enumerate(header):
            if col.startswith("quota_") and idx < len(r):
                try:
                    quotas[col] = int(r[idx])
                except ValueError:
                    quotas[col] = 0
        samples.append(Sample(step=step, load=load, ema=ema, quotas=quotas))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "-o", help="Path to save PNG plot; omit to show interactively.")
    args = parser.parse_args()

    samples = parse_csv(sys.stdin)
    steps = [s.step for s in samples]
    ema = [s.ema for s in samples]
    loads = [s.load for s in samples]

    fig, ax_left = plt.subplots(figsize=(10, 6))
    ax_left.plot(
        steps,
        ema,
        label="EMA load",
        color="tab:blue",
        marker="o",          # circle markers
        markersize=4,        # adjust size if needed
        markerfacecolor="white",
        markeredgewidth=1,
    )
    ax_left.set_xlabel("Step (5ms intervals)")
    ax_left.set_ylabel("EMA load", color="tab:blue")
    ax_left.tick_params(axis="y", labelcolor="tab:blue")

    #ax_right = ax_left.twinx()
    # Plot load as x-axis annotation by scaling; also overlay as markers
    # ax_right.plot(steps, loads, label="streams/5ms", color="tab:gray", alpha=0.3, linestyle="--")
    ax_left.plot(
        steps,
        loads,
        label="streams/5ms",
        color="tab:grey",
        alpha=0.5,
        linestyle="--",
        marker="o",          # circle markers
        markersize=4,        # adjust size if needed
        markerfacecolor="white",
        markeredgewidth=1,
    )

    ax_right = ax_left.twinx()
    # Plot quotas
    for quota_name in sorted(samples[0].quotas.keys()):
        series = [s.quotas.get(quota_name, 0) for s in samples]
        ax_right.plot(steps, series, label=quota_name, color="tab:orange")

    ax_right.set_ylabel("Quota (streams/100ms)", color="tab:orange")
    ax_right.tick_params(axis="y", labelcolor="tab:orange")

    # Legends
    lines_left, labels_left = ax_left.get_legend_handles_labels()
    lines_right, labels_right = ax_right.get_legend_handles_labels()
    ax_left.legend(lines_left + lines_right, labels_left + labels_right, loc="upper left")

    fig.tight_layout()
    if args.output:
        plt.savefig(args.output, dpi=150)
        print(f"Wrote plot to {args.output}")
    else:
        plt.show()


if __name__ == "__main__":
    main()
