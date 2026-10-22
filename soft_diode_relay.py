#!/usr/bin/env python3
"""Software one-way UDP relay (soft diode) for lab use, with optional impairment.

Listens on --listen and forwards datagrams ONLY to --forward.
Never opens a reverse path. Models a diode between pitcher and catcher
on one host or between two networks when bind/forward span interfaces.

  pitcher → :LISTEN  →  soft_diode_relay  →  :FORWARD  → catcher

Impairment (all off by default) makes it a lossy link for tests that cannot
use tc netem (macOS, CI without root): random or bursty loss, a blackout
window, duplication and reordering. Seed it for repeatable runs. Run a second
instance for the receipt direction to impair both ways.

Not a security accreditation boundary — only an algorithmic one-way hop.
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import sys
import time


class Impairment:
    """Decides the fate of each datagram. Pure apart from the RNG, so tests can drive it directly.

    Loss is a two-state Gilbert model: ``loss`` is the long-run drop rate and
    ``burst`` the mean length of a run of drops (1 = independent loss).
    """

    def __init__(
        self,
        loss: float = 0.0,
        burst: float = 1.0,
        dup: float = 0.0,
        reorder: float = 0.0,
        blackout: tuple[float, float] | None = None,
        seed: int | None = None,
    ) -> None:
        if not 0.0 <= loss < 1.0 or burst < 1.0:
            raise ValueError("loss must be in [0, 1) and burst >= 1")
        self.rng = random.Random(seed)
        self.loss = loss
        # P(bad -> good) = 1/burst; P(good -> bad) keeps the stationary drop rate at ``loss``.
        self.p_exit = 1.0 / burst
        self.p_enter = loss * self.p_exit / (1.0 - loss) if loss else 0.0
        self.bad = False
        self.dup = dup
        self.reorder = reorder
        self.blackout = blackout
        self.held: bytes | None = None
        self.stats = {"in": 0, "out": 0, "lost": 0, "blackout": 0, "dup": 0, "reordered": 0}

    def _lose(self) -> bool:
        if self.loss <= 0:
            return False
        if self.bad:
            self.bad = self.rng.random() >= self.p_exit
        else:
            self.bad = self.rng.random() < self.p_enter
        return self.bad

    def process(self, data: bytes, elapsed: float) -> list[bytes]:
        """Datagrams to forward now, in order, for one received datagram."""
        self.stats["in"] += 1
        if self.blackout is not None and self.blackout[0] <= elapsed < self.blackout[0] + self.blackout[1]:
            self.stats["blackout"] += 1
            return []
        if self._lose():
            self.stats["lost"] += 1
            return []
        out = [data]
        if self.dup and self.rng.random() < self.dup:
            out.append(data)
            self.stats["dup"] += 1
        if self.held is not None:
            out.append(self.held)  # released after the datagram that overtook it
            self.held = None
        elif self.reorder and self.rng.random() < self.reorder:
            self.held = out.pop(0)
            self.stats["reordered"] += 1
        self.stats["out"] += len(out)
        return out


def _blackout(value: str) -> tuple[float, float]:
    start, _, dur = value.partition(":")
    return float(start), float(dur)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--listen-host", default="127.0.0.1")
    p.add_argument("--listen-port", type=int, default=9401)
    p.add_argument("--forward-host", default="127.0.0.1")
    p.add_argument("--forward-port", type=int, default=9400)
    p.add_argument(
        "--forward-bind",
        default=None,
        help="Send from this local address (a second socket). Needed when the relay joins two "
        "networks: sending from the listen address would carry a source IP from the wrong network.",
    )
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--idle-exit", type=float, default=None)
    p.add_argument("--loss", type=float, default=0.0, help="Long-run drop probability (0-1)")
    p.add_argument("--burst", type=float, default=1.0, help="Mean length of a run of drops (1 = independent)")
    p.add_argument("--dup", type=float, default=0.0, help="Probability of sending a datagram twice")
    p.add_argument("--reorder", type=float, default=0.0, help="Probability of holding a datagram back by one")
    p.add_argument("--blackout", type=_blackout, default=None, metavar="START:SECONDS",
                   help="Drop everything for SECONDS, starting START seconds after the first datagram")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--stats-file", default=None, help="Write impairment counters here as JSON on exit")
    args = p.parse_args()
    imp = Impairment(args.loss, args.burst, args.dup, args.reorder, args.blackout, args.seed)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sock.bind((args.listen_host, args.listen_port))
    sock.settimeout(0.2)
    # Resolve once: sendto() with a hostname would do a DNS lookup per datagram.
    # Retry for a while so a container can start before its peer exists.
    fwd_ip = None
    for _ in range(150):
        try:
            fwd_ip = socket.gethostbyname(args.forward_host)
            break
        except OSError:
            time.sleep(0.2)
    if fwd_ip is None:
        print(f"cannot resolve {args.forward_host}", file=sys.stderr)
        return 1
    fwd = (fwd_ip, args.forward_port)
    out = sock
    if args.forward_bind:
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.bind((args.forward_bind, 0))  # send-only: nothing is ever read from it
    print(
        f"soft diode {args.listen_host}:{args.listen_port} → {fwd[0]}:{fwd[1]}",
        file=sys.stderr,
    )
    start = time.time()
    first: float | None = None
    last = start
    count = 0
    try:
        while True:
            now = time.time()
            if args.max_seconds is not None and now - start >= args.max_seconds:
                break
            if args.idle_exit is not None and count and now - last >= args.idle_exit:
                break
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            last = time.time()
            if first is None:
                first = last
            # One-way only: never sendto the source address.
            for dgram in imp.process(data, last - first):
                try:
                    out.sendto(dgram, fwd)
                except OSError:
                    pass  # receiver not up yet, or ICMP refused: a diode just loses it
            count += 1
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        if out is not sock:
            out.close()
        print(f"forwarded={count} impairment={json.dumps(imp.stats)}", file=sys.stderr)
        if args.stats_file:
            with open(args.stats_file, "w") as fh:
                json.dump(imp.stats, fh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
