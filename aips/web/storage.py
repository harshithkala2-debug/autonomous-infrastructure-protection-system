"""Protected storage for the AIPS web.

* Objects are content-addressed (SHA-256), compressed, written read-only (write once, read many) and, with the
  optional ``cryptography`` extra and a key, encrypted with AES-256-GCM. Every read re-hashes the content.
* The name -> version index is a hash-chained, HMAC-keyed ledger (the same tamper-evident ledger as the audit
  log). Editing, reordering or deleting an index line is detected by ``verify``.
* Nothing is ever overwritten. Deleting a name appends a tombstone, and only after its retention lock expired;
  the hub additionally requires a human approval for deletes.
* Replicas live on other nodes of the web. A corrupted or missing local object is repaired from a healthy replica
  (self-healing); a replica is only accepted if its content hash matches.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..backup.store import Cipher, IntegrityError, ObjectStore, atomic_write
from ..core.audit import AuditLedger


class RetentionLocked(PermissionError):
    pass


@dataclass
class Version:
    name: str
    version: int
    digest: str
    size: int
    by: str
    ts: float
    lock_until: float


class ProtectedStore:
    def __init__(self, root: str | Path, index_key: bytes, cipher: Cipher | None = None,
                 retention_s: float = 7 * 86400):
        self.root = Path(root)
        self.objects = ObjectStore(self.root / "data", cipher=cipher, worm=True)
        self.index = AuditLedger(self.root / "index.jsonl", key=index_key)
        self.retention_s = retention_s
        self._lock = threading.Lock()

    # -- index ---------------------------------------------------------------------------------------
    def _versions(self) -> dict[str, list[Version]]:
        out: dict[str, list[Version]] = {}
        for r in self.index.records():
            p = r.payload
            if r.event == "put":
                out.setdefault(p["name"], []).append(Version(p["name"], p["version"], p["digest"], p["size"],
                                                             r.actor, r.ts, p["lock_until"]))
            elif r.event == "delete":
                out.pop(p["name"], None)
        return out

    def names(self) -> list[str]:
        return sorted(self._versions())

    def versions(self, name: str) -> list[Version]:
        return list(self._versions().get(name, []))

    def verify(self) -> dict[str, Any]:
        ok, bad_seq, why = self.index.verify()
        bad_objects = []
        for vs in self._versions().values():
            for v in vs:
                try:
                    self.objects.get(v.digest)
                except IntegrityError:
                    bad_objects.append(v.digest)
        return {"index_ok": ok, "index_bad_seq": bad_seq, "index_detail": why,
                "objects": sum(len(v) for v in self._versions().values()), "bad_objects": sorted(set(bad_objects))}

    # -- data ----------------------------------------------------------------------------------------
    def put(self, name: str, data: bytes, by: str, now: float) -> Version:
        if not name or len(name) > 200 or ".." in name or name.startswith(("/", "\\")):
            raise ValueError("invalid object name")
        ok, _, why = self.index.verify()
        if not ok:
            raise IntegrityError(f"storage index failed verification ({why}); refusing writes")
        with self._lock:
            digest = self.objects.put(data)
            n = len(self.versions(name)) + 1
            lock_until = now + self.retention_s
            self.index.append(by, "put", {"name": name, "version": n, "digest": digest, "size": len(data),
                                          "lock_until": lock_until})
            return Version(name, n, digest, len(data), by, now, lock_until)

    def get(self, name: str, version: int | None = None) -> tuple[Version, bytes]:
        ok, _, why = self.index.verify()
        if not ok:
            raise IntegrityError(f"storage index failed verification ({why})")
        vs = self.versions(name)
        if not vs:
            raise KeyError(name)
        v = vs[-1] if version is None else next((x for x in vs if x.version == version), None)
        if v is None:
            raise KeyError(f"{name} v{version}")
        return v, self.objects.get(v.digest)

    def get_object(self, digest: str) -> bytes:
        return self.objects.get(digest)

    def put_object(self, data: bytes) -> str:
        return self.objects.put(data)

    def repair(self, digest: str, data: bytes) -> bool:
        """Replace a corrupted object with a verified good copy. Returns True when something was repaired."""
        if hashlib.sha256(data).hexdigest() != digest:
            raise IntegrityError("replacement copy does not match the expected hash; refused")
        try:
            self.objects.get(digest)
            return False
        except IntegrityError:
            pass
        p = self.objects._path(digest)
        if p.exists():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            p.unlink()
        self.objects.put(data, digest)
        return True

    def delete(self, name: str, by: str, now: float) -> None:
        vs = self.versions(name)
        if not vs:
            raise KeyError(name)
        until = max(v.lock_until for v in vs)
        if now < until:
            raise RetentionLocked(f"{name} is retention-locked for another {until - now:.0f}s")
        self.index.append(by, "delete", {"name": name})


def write_private(path: Path, data: bytes) -> None:
    atomic_write(path, data)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        pass
