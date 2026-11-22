"""Protected vault layer.

* Stored in a separate root (separate volume / host / account in production).
* Every operation passes an access gate restricted to the organisation's own
  networks. The allow-list lives only in the vault's private configuration;
  audit records carry a salted hash of the caller's IP, never the IP itself,
  so the network information is not disclosed through logs.
* Write-once: objects and manifests are written read-only and a retention
  lock prevents deletion of a snapshot before its lock expires - even by AIPS
  itself - which protects backups from an attacker who has compromised the
  main environment.
* Objects are re-verified (hash) on arrival; tampered manifests are rejected.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .store import Cipher, IntegrityError, Manifest, ObjectStore, atomic_write


class VaultAccessDenied(PermissionError):
    pass


class RetentionLocked(PermissionError):
    pass


@dataclass
class VaultConfig:
    root: str
    allowed_networks: list[str]
    retention_lock_s: float = 30 * 86400
    ip_hash_salt: str = ""


class Vault:
    def __init__(self, config: VaultConfig, hmac_key: bytes, cipher: Cipher | None = None):
        self.config = config
        self.hmac_key = hmac_key
        self._nets = [ipaddress.ip_network(n, strict=False) for n in config.allowed_networks]
        if not self._nets:
            raise ValueError("vault requires at least one allowed network")
        self.store = ObjectStore(config.root, cipher=cipher, worm=True)
        self._locks_path = Path(config.root) / "locks.json"
        self._locks: dict[str, float] = (json.loads(self._locks_path.read_text(encoding="utf-8"))
                                         if self._locks_path.exists() else {})
        self.access_log: list[dict] = []

    def caller_ref(self, ip: str | None) -> str:
        return hashlib.sha256(f"{self.config.ip_hash_salt}|{ip}".encode()).hexdigest()[:16]

    def _gate(self, source_ip: str | None, op: str) -> None:
        ok = False
        if source_ip:
            try:
                addr = ipaddress.ip_address(source_ip)
                ok = any(addr in n for n in self._nets)
            except ValueError:
                ok = False
        self.access_log.append({"op": op, "caller": self.caller_ref(source_ip), "allowed": ok})
        if not ok:
            raise VaultAccessDenied(f"vault {op} refused for caller {self.caller_ref(source_ip)}")

    def _save_locks(self) -> None:
        atomic_write(self._locks_path, json.dumps(self._locks).encode())

    def receive(self, manifest: Manifest, source: ObjectStore, source_ip: str | None, now: float) -> int:
        """Replicate a snapshot from the copy layer. Returns number of new objects."""
        self._gate(source_ip, "receive")
        if not manifest.verify(self.hmac_key):
            raise IntegrityError(f"manifest {manifest.id} signature invalid; refusing replication")
        if manifest.suspect:
            raise IntegrityError(f"snapshot {manifest.id} is flagged suspect; refusing replication")
        new = 0
        for entry in manifest.files.values():
            if not self.store.has(entry.sha256):
                self.store.put(source.get(entry.sha256), entry.sha256)   # get() re-verifies the hash
                new += 1
        self.store.save_manifest(manifest)
        self._locks[manifest.id] = now + self.config.retention_lock_s
        self._save_locks()
        return new

    def snapshots(self, source_ip: str | None) -> list[Manifest]:
        self._gate(source_ip, "list")
        return [m for m in self.store.manifests() if m.verify(self.hmac_key)]

    def fetch(self, digest: str, source_ip: str | None) -> bytes:
        self._gate(source_ip, "fetch")
        return self.store.get(digest)

    def locked_until(self, snapshot_id: str) -> float:
        return self._locks.get(snapshot_id, 0.0)

    def delete_snapshot(self, snapshot_id: str, source_ip: str | None, now: float) -> None:
        self._gate(source_ip, "delete")
        until = self._locks.get(snapshot_id, 0.0)
        if now < until:
            raise RetentionLocked(f"snapshot {snapshot_id} is retention-locked for another {until - now:.0f}s")
        self.store.delete_manifest(snapshot_id)
        self._locks.pop(snapshot_id, None)
        self._save_locks()
        referenced = {e.sha256 for m in self.store.manifests() for e in m.files.values()}
        for d in list(self.store.digests()):
            if d not in referenced:
                self.store.delete_object(d)

    def scrub(self) -> dict[str, int]:
        """Re-verify every object and manifest in the vault (no network gate: local maintenance)."""
        bad_objects = 0
        total = 0
        for d in self.store.digests():
            total += 1
            try:
                self.store.get(d)
            except IntegrityError:
                bad_objects += 1
        bad_manifests = sum(1 for m in self.store.manifests() if not m.verify(self.hmac_key))
        return {"objects": total, "bad_objects": bad_objects, "bad_manifests": bad_manifests}


def ensure_dir_private(path: str | os.PathLike) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:  # pragma: no cover - best effort on platforms without POSIX modes
        pass
