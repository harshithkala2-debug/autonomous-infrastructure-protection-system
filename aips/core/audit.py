"""Tamper-evident audit ledger.

Every decision, action, approval, freeze and appeal is appended as a record
whose hash covers the previous record's hash (a hash chain). With an HMAC key
configured, an attacker who can write the file still cannot forge a valid
chain without the key. ``verify`` reports the first broken record.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .clock import Clock, SystemClock
from .models import to_jsonable

GENESIS = "0" * 64


@dataclass
class AuditRecord:
    seq: int
    ts: float
    actor: str
    event: str
    payload: dict[str, Any]
    prev: str
    hash: str

    def body(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "actor": self.actor, "event": self.event,
                "payload": self.payload, "prev": self.prev}


class AuditLedger:
    def __init__(self, path: str | os.PathLike | None = None, key: bytes | None = None,
                 clock: Clock | None = None):
        self.path = Path(path) if path else None
        self.key = key
        self.clock = clock or SystemClock()
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []
        if self.path and self.path.exists():
            self._records = list(self._load())

    # -- hashing -------------------------------------------------------------
    def _digest(self, body: dict[str, Any]) -> str:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
        if self.key:
            return hmac.new(self.key, raw, hashlib.sha256).hexdigest()
        return hashlib.sha256(raw).hexdigest()

    # -- persistence ---------------------------------------------------------
    def _load(self) -> Iterator[AuditRecord]:
        assert self.path is not None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield AuditRecord(**json.loads(line))

    def _persist(self, rec: AuditRecord) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec.__dict__, sort_keys=True, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # -- API -----------------------------------------------------------------
    def append(self, actor: str, event: str, payload: Any = None) -> AuditRecord:
        with self._lock:
            prev = self._records[-1].hash if self._records else GENESIS
            seq = len(self._records) + 1
            body = {"seq": seq, "ts": self.clock.now(), "actor": actor, "event": event,
                    "payload": to_jsonable(payload or {}), "prev": prev}
            # normalise payload through JSON so verification sees identical values
            body["payload"] = json.loads(json.dumps(body["payload"], default=str))
            rec = AuditRecord(hash=self._digest(body), **body)
            self._records.append(rec)
            self._persist(rec)
            return rec

    def records(self, event_prefix: str | None = None, limit: int | None = None) -> list[AuditRecord]:
        with self._lock:
            recs = [r for r in self._records if not event_prefix or r.event.startswith(event_prefix)]
        return recs[-limit:] if limit else recs

    def __len__(self) -> int:
        return len(self._records)

    def verify(self) -> tuple[bool, int | None, str]:
        """Return (ok, first_bad_seq, reason)."""
        prev = GENESIS
        with self._lock:
            recs = list(self._records)
        for i, rec in enumerate(recs, start=1):
            if rec.seq != i:
                return False, rec.seq, "sequence gap or reorder"
            if rec.prev != prev:
                return False, rec.seq, "chain link mismatch"
            if not hmac.compare_digest(self._digest(rec.body()), rec.hash):
                return False, rec.seq, "record hash mismatch (modified)"
            prev = rec.hash
        return True, None, f"{len(recs)} records verified"

    @classmethod
    def verify_file(cls, path: str | os.PathLike, key: bytes | None = None) -> tuple[bool, int | None, str]:
        return cls(path, key=key).verify()
