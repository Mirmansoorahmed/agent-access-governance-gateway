"""Drift pin store (Check 3 state).

Maps ``(server, tool)`` to the approved pin hash plus provenance. The store is
append-only in spirit: a pin is set at approval time, and *resetting* it is an
explicit, recorded action (never implicit). The gateway itself never mutates a
pin as a side effect of a call.

Backed by a JSON file so it survives process restarts in the lab without a
database dependency.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class PinRecord:
    """One approved tool pin."""

    server: str
    tool: str
    pin_hash: str
    approved_by: str
    approved_at: str
    policy_version: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PinStore:
    """Thread-safe JSON-backed pin store.

    ``path=None`` keeps the store purely in memory (useful for tests).
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._pins: dict[tuple[str, str], PinRecord] = {}
        self._load()

    # --- persistence -----------------------------------------------------
    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        for entry in raw.get("pins", []):
            record = PinRecord(**entry)
            self._pins[(record.server, record.tool)] = record

    def _flush(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"pins": [asdict(record) for record in self._pins.values()]}
        self._path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    # --- API -------------------------------------------------------------
    def get(self, server: str, tool: str) -> str | None:
        """Return the approved pin hash for a tool, or ``None`` if unpinned."""
        with self._lock:
            record = self._pins.get((server, tool))
            return record.pin_hash if record is not None else None

    def set_pin(
        self,
        server: str,
        tool: str,
        pin_hash: str,
        approved_by: str,
        policy_version: str = "",
    ) -> PinRecord:
        """Record an approval pin for a tool (set at approval time)."""
        with self._lock:
            record = PinRecord(
                server=server,
                tool=tool,
                pin_hash=pin_hash,
                approved_by=approved_by,
                approved_at=_now(),
                policy_version=policy_version,
            )
            self._pins[(server, tool)] = record
            self._flush()
            return record

    def reset_pin(self, server: str, tool: str, approved_by: str) -> PinRecord | None:
        """Explicitly drop a pin (requires a recorded approver).

        Returns the removed record, or ``None`` if nothing was pinned. This is
        the *only* way a pin changes other than an initial ``set_pin`` -- the
        gateway never auto-resets.
        """
        if not approved_by:
            raise ValueError("pin reset requires a recorded approver id")
        with self._lock:
            removed = self._pins.pop((server, tool), None)
            if removed is not None:
                self._flush()
            return removed

    def records(self) -> list[PinRecord]:
        """Return all pin records (for the Tool Inventory report)."""
        with self._lock:
            return list(self._pins.values())
