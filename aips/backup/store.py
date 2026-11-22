"""Content-addressed object store with signed manifests.

Objects are keyed by the SHA-256 of their *plaintext*, compressed with zlib
and optionally encrypted with AES-256-GCM (requires the optional
``cryptography`` package; AIPS never ships home-made cryptography). Every read
re-hashes the plaintext, so silent corruption is always detected.

Manifests record every file in full detail (path, size, mode, mtime, hash) -
the backup preserves the data itself, not a summary - and are signed with
HMAC-SHA256 so a tampered manifest is rejected.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator


class IntegrityError(Exception):
    pass


class Cipher:
    """AES-256-GCM wrapper. ``key`` must be 32 bytes."""

    def __init__(self, key: bytes):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError("encryption requires the optional dependency: pip install 'aips[crypto]'") from exc
        if len(key) != 32:
            raise ValueError("backup encryption key must be 32 bytes (64 hex characters)")
        self._aes = AESGCM(key)

    def encrypt(self, data: bytes, aad: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, data, aad)

    def decrypt(self, blob: bytes, aad: bytes) -> bytes:
        return self._aes.decrypt(blob[:12], blob[12:], aad)


MAGIC_PLAIN = b"AIPS0"
MAGIC_ENC = b"AIPS1"


@dataclass
class FileEntry:
    sha256: str
    size: int
    mode: int
    mtime: float


@dataclass
class Manifest:
    id: str
    created_at: float
    source: str
    files: dict[str, FileEntry]
    parent: str | None = None
    suspect: bool = False
    notes: list[str] = field(default_factory=list)
    signature: str = ""

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("signature")
        return d

    def sign(self, key: bytes) -> None:
        self.signature = hmac.new(key, _canon(self.body()), hashlib.sha256).hexdigest()

    def verify(self, key: bytes) -> bool:
        expected = hmac.new(key, _canon(self.body()), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files.values())

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=1, sort_keys=True)

    @classmethod
    def from_json(cls, s: str) -> "Manifest":
        d = json.loads(s)
        d["files"] = {k: FileEntry(**v) for k, v in d["files"].items()}
        return cls(**d)


def _canon(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path: Path, bufsize: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(bufsize):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: Path, data: bytes, read_only: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    if read_only:
        os.chmod(path, stat.S_IREAD)


class ObjectStore:
    def __init__(self, root: str | os.PathLike, cipher: Cipher | None = None, worm: bool = False):
        self.root = Path(root)
        self.cipher = cipher
        self.worm = worm
        (self.root / "objects").mkdir(parents=True, exist_ok=True)
        (self.root / "manifests").mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"invalid digest {digest!r}")
        return self.root / "objects" / digest[:2] / digest

    def has(self, digest: str) -> bool:
        return self._path(digest).exists()

    def put(self, data: bytes, digest: str | None = None) -> str:
        digest = digest or hashlib.sha256(data).hexdigest()
        p = self._path(digest)
        if p.exists():
            return digest
        packed = zlib.compress(data, 6)
        if self.cipher:
            blob = MAGIC_ENC + self.cipher.encrypt(packed, digest.encode())
        else:
            blob = MAGIC_PLAIN + packed
        atomic_write(p, blob, read_only=self.worm)
        return digest

    def get(self, digest: str) -> bytes:
        p = self._path(digest)
        if not p.exists():
            raise IntegrityError(f"object {digest[:12]} missing")
        blob = p.read_bytes()
        try:
            if blob.startswith(MAGIC_ENC):
                if not self.cipher:
                    raise IntegrityError("object is encrypted but no key is configured")
                packed = self.cipher.decrypt(blob[5:], digest.encode())
            elif blob.startswith(MAGIC_PLAIN):
                packed = blob[5:]
            else:
                raise IntegrityError(f"object {digest[:12]} has unknown format")
            data = zlib.decompress(packed)
        except IntegrityError:
            raise
        except Exception as exc:  # noqa: BLE001 - any decode failure is corruption
            raise IntegrityError(f"object {digest[:12]} unreadable: {exc}") from exc
        if hashlib.sha256(data).hexdigest() != digest:
            raise IntegrityError(f"object {digest[:12]} content hash mismatch")
        return data

    def digests(self) -> Iterator[str]:
        for sub in (self.root / "objects").iterdir():
            if sub.is_dir():
                for f in sub.iterdir():
                    if not f.name.startswith(".tmp-"):
                        yield f.name

    def delete_object(self, digest: str) -> None:
        p = self._path(digest)
        if p.exists():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            p.unlink()

    # -- manifests -----------------------------------------------------------
    def save_manifest(self, m: Manifest) -> None:
        atomic_write(self.root / "manifests" / f"{m.id}.json", m.to_json().encode(), read_only=self.worm)

    def load_manifest(self, snapshot_id: str) -> Manifest:
        if "/" in snapshot_id or "\\" in snapshot_id or ".." in snapshot_id:
            raise ValueError("invalid snapshot id")
        return Manifest.from_json((self.root / "manifests" / f"{snapshot_id}.json").read_text(encoding="utf-8"))

    def manifests(self) -> list[Manifest]:
        out = [Manifest.from_json(p.read_text(encoding="utf-8"))
               for p in (self.root / "manifests").glob("*.json")]
        return sorted(out, key=lambda m: (m.created_at, m.id))

    def delete_manifest(self, snapshot_id: str) -> None:
        p = self.root / "manifests" / f"{snapshot_id}.json"
        if p.exists():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            p.unlink()
