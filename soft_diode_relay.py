#!/usr/bin/env python3
"""Software one-way UDP relay (soft diode) for lab use.

Listens on --listen and forwards datagrams ONLY to --forward.
Never opens a reverse path. Models a diode between pitcher and catcher
on one host or between two networks when bind/forward span interfaces.

  pitcher → :LISTEN  →  soft_diode_relay  →  :FORWARD  → catcher

Not a security accreditation boundary — only an algorithmic one-way hop.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time


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
    args = p.parse_args()

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
            # One-way only: never sendto the source address.
            out.sendto(data, fwd)
            count += 1
            last = time.time()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        if out is not sock:
            out.close()
        print(f"forwarded={count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
