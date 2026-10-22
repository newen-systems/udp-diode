#!/usr/bin/env python3
"""Chunk-level Monte Carlo of no-feedback FEC layouts under soft_diode_relay loss.

Fast stand-in for the end-to-end bench: no sockets, no hashing. Models the
frame order a sender emits, pushes it through the same Impairment model the
relay uses, then runs a peeling decoder (any XOR group missing exactly one
member is repaired; repeat until nothing changes). Use it to pick a layout,
then confirm the pick with scripts/bench_toggles.py.

  python3 scripts/fec_sim.py --chunks 13981 --loss 0.01 --burst 6 --runs 200

A layout is a list of parity families (group, stride) plus a pass count.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol import parity_groups  # noqa: E402
from soft_diode_relay import Impairment  # noqa: E402


def frame_order(n: int, families: list[tuple[int, int]], spread: bool) -> list[tuple]:
    """('d', seq) and ('p', group_id) in send order.

    spread=False: each family's parities for a block go out together after the block (current sender).
    spread=True: each parity goes out right after its last member, so parities interleave with data.
    """
    groups: list[list[int]] = []
    for k, d in families:
        groups.extend(parity_groups(n, k, d))
    after: dict[int, list[int]] = {}
    for gid, g in enumerate(groups):
        if spread:
            key = g[-1]
        else:
            k, d = families[0] if len(families) == 1 else _family_of(gid, n, families)
            block = k * d
            key = min(n - 1, (g[0] // block) * block + block - 1)
        after.setdefault(key, []).append(gid)
    order: list[tuple] = []
    for s in range(n):
        order.append(("d", s))
        order.extend(("p", gid) for gid in after.get(s, ()))
    return order, groups


def _family_of(gid: int, n: int, families: list[tuple[int, int]]) -> tuple[int, int]:
    for k, d in families:
        count = sum(1 for _ in parity_groups(n, k, d))
        if gid < count:
            return k, d
        gid -= count
    raise IndexError(gid)


def decode(n: int, groups: list[list[int]], have_data: set[int], have_par: set[int]) -> int:
    """Peeling decoder. Returns chunks still missing."""
    missing = set(range(n)) - have_data
    members: dict[int, list[int]] = {}
    for gid in have_par:
        for s in groups[gid]:
            members.setdefault(s, []).append(gid)
    work = [gid for gid in have_par]
    while work and missing:
        nxt = []
        for gid in work:
            gone = [s for s in groups[gid] if s in missing]
            if len(gone) == 1:
                s = gone[0]
                missing.discard(s)
                nxt.extend(members.get(s, ()))
        work = nxt
    return len(missing)


def run(n: int, families: list[tuple[int, int]], passes: int, spread: bool,
        imp_args: dict, runs: int) -> dict:
    order, groups = frame_order(n, families, spread)
    ok = 0
    residual = []
    for seed in range(runs):
        imp = Impairment(seed=seed, **imp_args)
        have_d: set[int] = set()
        have_p: set[int] = set()
        for _ in range(passes):
            for kind, x in order:
                if imp.process(b"x", 0.0):
                    (have_d if kind == "d" else have_p).add(x)
        left = decode(n, groups, have_d, have_p)
        ok += left == 0
        residual.append(left)
    overhead = passes * (n + len(groups)) / n
    return {"ok": ok, "runs": runs, "overhead": round(overhead, 3),
            "goodput_at_18": round(18 / overhead / 1.07, 2),  # 1.07: frame header bytes at chunk 1200
            "residual_median": sorted(residual)[len(residual) // 2], "residual_max": max(residual)}


LAYOUTS = {
    "fec4 x2 passes (WAN-BALANCE)": ([(4, 1)], 2, False),
    "fec4 stride16": ([(4, 16)], 1, False),
    "fec4 stride64": ([(4, 64)], 1, False),
    "fec4 stride64 spread": ([(4, 64)], 1, True),
    "2 families g8 s64+s72": ([(8, 64), (8, 72)], 1, False),
    "2 families g8 s64+s72 spread": ([(8, 64), (8, 72)], 1, True),
    "2 families g4 s64+s68 spread": ([(4, 64), (4, 68)], 1, True),
    "2 families g6 s64+s70 spread": ([(6, 64), (6, 70)], 1, True),
    "3 families g8 s64+s72+s80 spread": ([(8, 64), (8, 72), (8, 80)], 1, True),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--chunks", type=int, default=13981, help="16 MiB at chunk 1200")
    ap.add_argument("--loss", type=float, default=0.01)
    ap.add_argument("--burst", type=float, default=6.0)
    ap.add_argument("--runs", type=int, default=100)
    ap.add_argument("--layouts", default=",".join(LAYOUTS))
    args = ap.parse_args()
    imp = {"loss": args.loss, "burst": args.burst}
    print(f"chunks={args.chunks} loss={args.loss} burst={args.burst} runs={args.runs}")
    for name in args.layouts.split(","):
        fam, passes, spread = LAYOUTS[name]
        r = run(args.chunks, fam, passes, spread, imp, args.runs)
        print(f"{name:36} ok={r['ok']}/{r['runs']} overhead={r['overhead']} "
              f"goodput@18={r['goodput_at_18']} residual med={r['residual_median']} max={r['residual_max']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
