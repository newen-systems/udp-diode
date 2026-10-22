#!/usr/bin/env python3
"""Role launcher for the container image: DIODE_MODE=sender|receiver.

    diode.py                run the role named by DIODE_MODE
    diode.py sender         same, role given on the command line (must match DIODE_MODE if set)
    diode.py --check-config validate the environment, print the effective config, exit
    diode.py --healthcheck  GET /readyz on this container's own HTTP port; exit 0 if ready (for HEALTHCHECK)

Exit codes: 0 clean stop (SIGTERM/SIGINT), 2 invalid configuration, 1 runtime failure.
All configuration is environment variables; secrets are file paths. See README.
"""
from __future__ import annotations

import os
import signal
import sys
import threading

from diode_config import ConfigError, load


def healthcheck() -> int:
    import http.client
    import ssl

    port = int(os.environ.get("DIODE_HTTP_PORT", "8080"))
    try:
        if os.environ.get("DIODE_TLS_CERT_FILE"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # loopback probe of our own listener
            ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=ctx)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/readyz")
        return 0 if conn.getresponse().status == 200 else 1
    except (OSError, http.client.HTTPException):
        return 1


def main(argv: list[str]) -> int:
    if "--healthcheck" in argv:
        return healthcheck()
    check = "--check-config" in argv
    roles = [a for a in argv if a in ("sender", "receiver")]
    env = dict(os.environ)
    if roles:
        if env.get("DIODE_MODE") not in (None, "", roles[0]):
            print(f"config error: DIODE_MODE={env['DIODE_MODE']} contradicts argument {roles[0]}", file=sys.stderr)
            return 2
        env["DIODE_MODE"] = roles[0]
    try:
        cfg = load(env)
    except ConfigError as exc:
        print("config error:\n  " + str(exc).replace("\n", "\n  "), file=sys.stderr)
        return 2
    if check:
        for key, value in sorted(cfg.redacted().items()):
            print(f"{key}={value}")
        return 0

    stop = threading.Event()

    def on_signal(signum: int, _frame: object) -> None:
        print(f"signal {signum}: stopping", file=sys.stderr)
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    if cfg.mode == "sender":
        from diode_sender import SenderService

        sender = SenderService(cfg)
        sender.start()
        try:
            stop.wait()
        finally:
            sender.stop()
        return 0

    from diode_receiver import ReceiverService

    receiver = ReceiverService(cfg)
    receiver.start()
    watcher = threading.Thread(target=lambda: (stop.wait(), receiver.stop_event.set()), daemon=True)
    watcher.start()
    try:
        receiver.run()
    finally:
        receiver.stop()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except OSError as exc:  # port in use, unreadable state dir, ...
        print(f"fatal: {exc}", file=sys.stderr)
        raise SystemExit(1)
