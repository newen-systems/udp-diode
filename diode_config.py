"""Environment configuration for the sender and receiver services.

Everything is validated up front; a bad value stops the process at startup
with one message per problem instead of failing later under load.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from protocol import DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MAX_PARITY_GROUP, STATUS_MISSING_MAX, max_datagram_len

MODES = ("sender", "receiver")
FEEDBACK = ("off", "receipts")
GiB = 1024**3
MiB = 1024**2


class ConfigError(ValueError):
    """All problems found, one per line."""


@dataclass(frozen=True)
class Config:
    mode: str
    feedback: str
    state_dir: Path
    http_bind: str = "0.0.0.0"
    http_port: int = 8080
    tls_cert_file: Path | None = None
    tls_key_file: Path | None = None
    api_token: bytes = b""
    data_key: bytes = b""
    receipt_key: bytes | None = None
    # transport tuning (shared)
    mtu: int = 1500
    chunk_size: int = DEFAULT_CHUNK_SIZE
    holes_window: int = 64
    # http limits
    http_io_timeout_s: float = 30.0
    header_deadline_s: float = 10.0
    upload_deadline_s: float = 3600.0
    max_connections: int = 32
    # sender
    data_peer: tuple[str, int] | None = None
    receipt_bind: tuple[str, int] = ("0.0.0.0", 9401)
    max_bitrate_mbps: float = 100.0
    parity_group: int = 0
    meta_copies: int = 3
    eof_copies: int = 3
    passes: int = 1
    gap_ms: float = 0.0
    sndbuf: int = 0
    send_concurrency: int = 2
    max_body_bytes: int = 16 * GiB
    disk_reserve_bytes: int = 256 * MiB
    spool_quota_bytes: int = 64 * GiB
    max_uploads: int = 4
    ack_timeout_s: float = 2.0
    ack_backoff: float = 1.5
    ack_timeout_cap_s: float = 10.0
    retry_budget_s: float = 3600.0
    spool_retention_s: float = 86400.0
    failed_retention_s: float = 7 * 86400.0
    ledger_retention_s: float = 30 * 86400.0
    # receiver
    data_bind: tuple[str, int] = ("0.0.0.0", 9400)
    receipt_peer: tuple[str, int] | None = None
    delivery_url: str = ""
    delivery_token: bytes | None = None
    delivery_ca_file: Path | None = None
    delivery_timeout_s: float = 60.0
    delivery_backoff_min_s: float = 1.0
    delivery_backoff_max_s: float = 300.0
    delivery_concurrency: int = 2
    rcvbuf: int = 0
    ram_max_bytes: int = 64 * MiB
    ram_budget_bytes: int = 256 * MiB
    max_transfer_bytes: int = 16 * GiB
    max_active: int = 16
    min_free_bytes: int = 256 * MiB
    ttl_s: float = 3600.0
    receipt_every: int = 0
    receipt_interval_s: float = 1.0
    receipt_retention_s: float = 300.0
    receipt_copies: int = 3
    dedupe_retention_s: float = 7 * 86400.0

    def redacted(self) -> dict:
        out = {}
        for k, v in self.__dict__.items():
            if k in ("api_token", "data_key", "receipt_key", "delivery_token"):
                out[k] = "set" if v else "unset"
            elif isinstance(v, Path):
                out[k] = str(v)
            else:
                out[k] = v
        return out


class _Reader:
    def __init__(self, env: Mapping[str, str]) -> None:
        self.env = env
        self.errors: list[str] = []

    def _raw(self, name: str) -> str | None:
        value = self.env.get(name)
        return value.strip() if value is not None and value.strip() != "" else None

    def text(self, name: str, default: str | None = None, choices: tuple[str, ...] | None = None) -> str:
        value = self._raw(name)
        if value is None:
            if default is None:
                self.errors.append(f"{name} is required")
                return ""
            return default
        if choices is not None and value not in choices:
            self.errors.append(f"{name}={value!r} must be one of {', '.join(choices)}")
            return default or ""
        return value

    def number(self, name: str, default: float, lo: float, hi: float, integer: bool = False) -> float:
        value = self._raw(name)
        if value is None:
            return int(default) if integer else default
        try:
            num = int(value, 10) if integer else float(value)
        except ValueError:
            self.errors.append(f"{name}={value!r} is not {'an integer' if integer else 'a number'}")
            return default
        if not lo <= num <= hi or num != num:
            self.errors.append(f"{name}={value} must be between {lo:g} and {hi:g}")
            return default
        return num

    def int_(self, name: str, default: int, lo: int, hi: int) -> int:
        return int(self.number(name, default, lo, hi, integer=True))

    def hostport(self, name: str, required: bool, default_port: int | None = None) -> tuple[str, int] | None:
        value = self._raw(name)
        if value is None:
            if required:
                self.errors.append(f"{name} is required (host:port)")
            return None
        host, sep, port = value.rpartition(":")
        if not sep and default_port is not None:
            host, port = value, str(default_port)
        elif not sep:
            self.errors.append(f"{name}={value!r} must be host:port")
            return None
        if not host or not port.isdigit() or not 1 <= int(port) <= 65535 or " " in host:
            self.errors.append(f"{name}={value!r} must be host:port with port 1-65535")
            return None
        return host, int(port)

    def secret(self, name: str, required: bool) -> bytes | None:
        value = self._raw(name)
        if value is None:
            if required:
                self.errors.append(f"{name} is required (path of a secret file)")
            return None
        path = Path(value)
        try:
            data = path.read_bytes().strip()
        except OSError as exc:
            self.errors.append(f"{name}: cannot read {value}: {exc.strerror}")
            return None
        if len(data) < 16:
            self.errors.append(f"{name}: secret in {value} must be at least 16 bytes")
            return None
        return data

    def path(self, name: str, required: bool = False) -> Path | None:
        value = self._raw(name)
        if value is None:
            if required:
                self.errors.append(f"{name} is required")
            return None
        return Path(value)


def load(env: Mapping[str, str] | None = None) -> Config:
    """Build a Config from the environment or raise ConfigError listing every problem."""
    r = _Reader(os.environ if env is None else env)
    mode = r.text("DIODE_MODE", choices=MODES)
    feedback = r.text("DIODE_FEEDBACK", "off", FEEDBACK)
    sender, receiver = mode == "sender", mode == "receiver"
    receipts = feedback == "receipts"

    state_dir = r.path("DIODE_STATE_DIR", required=True) or Path(".")
    if r._raw("DIODE_STATE_DIR"):
        try:
            state_dir.mkdir(parents=True, exist_ok=True)
            probe = state_dir / ".write-probe"
            probe.write_text("x")
            probe.unlink()
        except OSError as exc:
            r.errors.append(f"DIODE_STATE_DIR {state_dir} is not writable: {exc.strerror}")

    api_token = r.secret("DIODE_API_TOKEN_FILE", required=True)
    data_key = r.secret("DIODE_DATA_KEY_FILE", required=True)
    receipt_key = r.secret("DIODE_RECEIPT_KEY_FILE", required=receipts)
    if receipts and receipt_key is not None and receipt_key == data_key:
        r.errors.append("DIODE_RECEIPT_KEY_FILE must differ from DIODE_DATA_KEY_FILE")
    if not receipts and r._raw("DIODE_RECEIPT_KEY_FILE"):
        r.errors.append("DIODE_RECEIPT_KEY_FILE is set but DIODE_FEEDBACK=off")

    mtu = r.int_("DIODE_MTU", 1500, 576, 9216)
    chunk = r.int_("DIODE_CHUNK_SIZE", DEFAULT_CHUNK_SIZE, 64, MAX_CHUNK_SIZE)
    holes = r.int_("DIODE_HOLES_WINDOW", 64, 1, STATUS_MISSING_MAX)
    parity = r.int_("DIODE_PARITY_GROUP", 0, 0, MAX_PARITY_GROUP)
    if parity == 1:
        r.errors.append("DIODE_PARITY_GROUP=1 is meaningless; use 0 (off) or 2 and up")
    if max_datagram_len(chunk) > mtu - 28:
        r.errors.append(
            f"DIODE_CHUNK_SIZE={chunk} makes a {max_datagram_len(chunk)} byte datagram; "
            f"DIODE_MTU={mtu} allows {mtu - 28}. Lower the chunk size (never rely on IP fragmentation)"
        )

    tls_cert, tls_key = r.path("DIODE_TLS_CERT_FILE"), r.path("DIODE_TLS_KEY_FILE")
    if bool(tls_cert) != bool(tls_key):
        r.errors.append("DIODE_TLS_CERT_FILE and DIODE_TLS_KEY_FILE must be set together")
    for name, p in (("DIODE_TLS_CERT_FILE", tls_cert), ("DIODE_TLS_KEY_FILE", tls_key)):
        if p is not None and not p.is_file():
            r.errors.append(f"{name}: {p} is not a file")

    kw: dict = dict(
        mode=mode,
        feedback=feedback,
        state_dir=state_dir,
        http_bind=r.text("DIODE_HTTP_BIND", "0.0.0.0"),
        http_port=r.int_("DIODE_HTTP_PORT", 8080, 1, 65535),
        tls_cert_file=tls_cert,
        tls_key_file=tls_key,
        api_token=api_token or b"",
        data_key=data_key or b"",
        receipt_key=receipt_key,
        mtu=mtu,
        chunk_size=chunk,
        holes_window=holes,
        http_io_timeout_s=r.number("DIODE_HTTP_IO_TIMEOUT_S", 30.0, 1, 600),
        header_deadline_s=r.number("DIODE_HEADER_DEADLINE_S", 10.0, 1, 600),
        upload_deadline_s=r.number("DIODE_UPLOAD_DEADLINE_S", 3600.0, 5, 86400),
        max_connections=r.int_("DIODE_MAX_CONNECTIONS", 32, 1, 1024),
    )

    if sender:
        peer = r.hostport("DIODE_DATA_PEER", required=True)
        rbind = r.hostport("DIODE_RECEIPT_BIND", required=False, default_port=9401)
        if r._raw("DIODE_RECEIPT_PEER"):
            r.errors.append("DIODE_RECEIPT_PEER belongs to the receiver")
        kw.update(
            data_peer=peer,
            receipt_bind=rbind or ("0.0.0.0", 9401),
            max_bitrate_mbps=r.number("DIODE_MAX_BITRATE_MBPS", 100.0, 0.001, 100000),
            parity_group=parity,
            meta_copies=r.int_("DIODE_META_COPIES", 3, 1, 20),
            eof_copies=r.int_("DIODE_EOF_COPIES", 3, 1, 20),
            passes=r.int_("DIODE_PASSES", 1, 1, 20),
            gap_ms=r.number("DIODE_GAP_MS", 0.0, 0, 1000),
            sndbuf=r.int_("DIODE_SNDBUF", 0, 0, 1 << 30),
            send_concurrency=r.int_("DIODE_SEND_CONCURRENCY", 2, 1, 32),
            max_body_bytes=r.int_("DIODE_MAX_BODY_BYTES", 16 * GiB, 0, 1 << 50),
            disk_reserve_bytes=r.int_("DIODE_DISK_RESERVE_BYTES", 256 * MiB, 0, 1 << 50),
            spool_quota_bytes=r.int_("DIODE_SPOOL_QUOTA_BYTES", 64 * GiB, 1, 1 << 50),
            max_uploads=r.int_("DIODE_MAX_UPLOADS", 4, 1, 256),
            ack_timeout_s=r.number("DIODE_ACK_TIMEOUT_S", 2.0, 0.05, 600),
            ack_backoff=r.number("DIODE_ACK_BACKOFF", 1.5, 1.0, 10),
            ack_timeout_cap_s=r.number("DIODE_ACK_TIMEOUT_CAP_S", 10.0, 0.05, 3600),
            retry_budget_s=r.number("DIODE_RETRY_BUDGET_S", 3600.0, 1, 30 * 86400),
            spool_retention_s=r.number("DIODE_SPOOL_RETENTION_S", 86400.0, 1, 365 * 86400),
            failed_retention_s=r.number("DIODE_FAILED_RETENTION_S", 7 * 86400.0, 1, 365 * 86400),
            ledger_retention_s=r.number("DIODE_LEDGER_RETENTION_S", 30 * 86400.0, 1, 3650 * 86400),
        )
        if not receipts and (r._raw("DIODE_RECEIPT_BIND")):
            r.errors.append("DIODE_RECEIPT_BIND is set but DIODE_FEEDBACK=off (no receipt socket is opened)")
    if receiver:
        url = r.text("DIODE_DELIVERY_URL")
        if url:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                r.errors.append(f"DIODE_DELIVERY_URL={url!r} must be an http:// or https:// URL")
        bind = r.hostport("DIODE_DATA_BIND", required=False, default_port=9400)
        rpeer = r.hostport("DIODE_RECEIPT_PEER", required=receipts)
        if not receipts and r._raw("DIODE_RECEIPT_PEER"):
            r.errors.append("DIODE_RECEIPT_PEER is set but DIODE_FEEDBACK=off (no receipt socket is opened)")
        if r._raw("DIODE_DATA_PEER"):
            r.errors.append("DIODE_DATA_PEER belongs to the sender")
        ca = r.path("DIODE_DELIVERY_CA_FILE")
        if ca is not None and not ca.is_file():
            r.errors.append(f"DIODE_DELIVERY_CA_FILE: {ca} is not a file")
        kw.update(
            data_bind=bind or ("0.0.0.0", 9400),
            receipt_peer=rpeer,
            delivery_url=url,
            delivery_token=r.secret("DIODE_DELIVERY_TOKEN_FILE", required=False),
            delivery_ca_file=ca,
            delivery_timeout_s=r.number("DIODE_DELIVERY_TIMEOUT_S", 60.0, 1, 3600),
            delivery_backoff_min_s=r.number("DIODE_DELIVERY_BACKOFF_MIN_S", 1.0, 0.1, 3600),
            delivery_backoff_max_s=r.number("DIODE_DELIVERY_BACKOFF_MAX_S", 300.0, 0.1, 86400),
            delivery_concurrency=r.int_("DIODE_DELIVERY_CONCURRENCY", 2, 1, 16),
            rcvbuf=r.int_("DIODE_RCVBUF", 0, 0, 1 << 30),
            ram_max_bytes=r.int_("DIODE_RAM_MAX_BYTES", 64 * MiB, 0, 1 << 40),
            ram_budget_bytes=r.int_("DIODE_RAM_BUDGET_BYTES", 256 * MiB, 0, 1 << 40),
            max_transfer_bytes=r.int_("DIODE_MAX_TRANSFER_BYTES", 16 * GiB, 1, 1 << 50),
            max_active=r.int_("DIODE_MAX_ACTIVE", 16, 1, 4096),
            min_free_bytes=r.int_("DIODE_MIN_FREE_BYTES", 256 * MiB, 0, 1 << 50),
            ttl_s=r.number("DIODE_TTL_S", 3600.0, 1, 30 * 86400),
            receipt_every=r.int_("DIODE_RECEIPT_EVERY", 0, 0, 1_000_000),
            receipt_interval_s=r.number("DIODE_RECEIPT_INTERVAL_S", 1.0, 0.05, 600),
            receipt_retention_s=r.number("DIODE_RECEIPT_RETENTION_S", 300.0, 1, 30 * 86400),
            receipt_copies=r.int_("DIODE_RECEIPT_COPIES", 3, 1, 20),
            dedupe_retention_s=r.number("DIODE_DEDUPE_RETENTION_S", 7 * 86400.0, 1, 3650 * 86400),
        )
        if kw["delivery_backoff_min_s"] > kw["delivery_backoff_max_s"]:
            r.errors.append("DIODE_DELIVERY_BACKOFF_MIN_S must not exceed DIODE_DELIVERY_BACKOFF_MAX_S")
    if receiver and not r._raw("DIODE_DELIVERY_URL"):
        r.errors.append("DIODE_DELIVERY_URL is required")
    if r.errors:
        raise ConfigError("\n".join(dict.fromkeys(r.errors)))
    return Config(**kw)
