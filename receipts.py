"""Local receipt drop-dir — the coordinator's language.

Catchers write JSON here. Pitchers read JSON here. Neither opens a socket
in the opposite direction. The two UDP tracks never share a directory;
a same-side coordinator copies an allowlisted schema from catcher outbox
to pitcher inbox.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from protocol import (
    STATUS_FAIL,
    STATUS_MISSING_MAX,
    ProtocolError,
    StatusReport,
    check_report_fields,
    valid_transfer_id,
)

RECEIPT_KEYS = (
    "transfer_id",
    "kind",
    "have",
    "total_chunks",
    "missing",
    "reason",
)
SOURCE_KEYS = ("transfer_id", "path", "chunk_size", "parity_group")


def report_to_dict(report: StatusReport) -> dict:
    return {
        "transfer_id": report.transfer_id,
        "kind": report.kind,
        "have": report.have,
        "total_chunks": report.total_chunks,
        "missing": list(report.missing)[:STATUS_MISSING_MAX],
        "reason": report.reason if report.kind == STATUS_FAIL else None,
    }


def report_from_dict(data: dict) -> StatusReport:
    """Strict projection of a local receipt file onto the receipt schema.

    Unknown keys are dropped (allowlist), but every known field must have the
    exact type and bounds. Nothing is coerced and nothing is truncated.
    """
    if type(data) is not dict:
        raise ProtocolError("receipt is not a JSON object")
    kind = data.get("kind")
    missing = data.get("missing")
    reason = data.get("reason")
    transfer_id = data.get("transfer_id")
    have = data.get("have")
    total = data.get("total_chunks")
    if missing is None:
        missing = []
    check_report_fields(transfer_id, kind, have, total, missing, reason)
    return StatusReport(
        transfer_id=transfer_id,
        kind=kind,
        have=have,
        total_chunks=total,
        missing=tuple(missing),
        reason=reason if kind == STATUS_FAIL else None,
    )


def allowlist_receipt(data: dict) -> dict:
    """Drop any key the reverse track must not carry."""
    report = report_from_dict(data)
    return report_to_dict(report)


@dataclass
class ReceiptStore:
    directory: Path

    def __post_init__(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)

    def path_for(self, transfer_id: str) -> Path:
        if not valid_transfer_id(transfer_id):
            raise ValueError(f"invalid transfer id {transfer_id!r}")
        return self.directory / f"{transfer_id}.json"

    def write(self, report: StatusReport) -> Path:
        path = self.path_for(report.transfer_id)
        data = report_to_dict(report)
        report_from_dict(data)  # never persist what no reader would accept
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n")
        tmp.replace(path)
        return path

    def read(self, transfer_id: str) -> StatusReport | None:
        """Current receipt, or None when absent or not a valid receipt."""
        path = self.path_for(transfer_id)
        try:
            return report_from_dict(json.loads(path.read_text()))
        except (OSError, ValueError, RecursionError):
            return None

    def delete(self, transfer_id: str) -> None:
        self.path_for(transfer_id).unlink(missing_ok=True)

    def touch(self, transfer_id: str) -> bool:
        """Refresh a receipt's age so it is repeated again; False when absent."""
        try:
            os.utime(self.path_for(transfer_id))
        except OSError:
            return False
        return True

    def list_reports(self) -> list[tuple[Path, StatusReport]]:
        out: list[tuple[Path, StatusReport]] = []
        for path in sorted(self.directory.glob("*.json")):
            if path.name.endswith(".tmp"):
                continue
            try:
                report = report_from_dict(json.loads(path.read_text()))
            except (OSError, ValueError, RecursionError):
                continue
            if path.stem != report.transfer_id:
                continue
            out.append((path, report))
        return out


def write_source_map(
    directory: Path,
    transfer_id: str,
    path: Path,
    chunk_size: int,
    parity_group: int = 0,
) -> Path:
    if not valid_transfer_id(transfer_id):
        raise ValueError(f"invalid transfer id {transfer_id!r}")
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / f"{transfer_id}.json"
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(
            {
                "transfer_id": transfer_id,
                "path": str(path),
                "chunk_size": chunk_size,
                "parity_group": parity_group,
            },
            indent=2,
        )
        + "\n"
    )
    tmp.replace(dest)
    return dest


def read_source_map(directory: Path, transfer_id: str) -> dict | None:
    if not valid_transfer_id(transfer_id):
        raise ValueError(f"invalid transfer id {transfer_id!r}")
    path = directory / f"{transfer_id}.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text())
    if "path" not in data or "chunk_size" not in data:
        return None
    return {
        "transfer_id": str(data.get("transfer_id", transfer_id)),
        "path": Path(str(data["path"])),
        "chunk_size": int(data["chunk_size"]),
        "parity_group": int(data.get("parity_group") or 0),
    }
