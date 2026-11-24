"""Closed trust domain for the AIPS web.

Only machines holding a credential issued by the domain authority can talk to the web. The authority (the hub)
keeps one 256-bit domain secret and derives each node's key from it:

    node_key = HMAC-SHA256(domain_secret, "aips-web|<domain>|<node>|<epoch>")

so the hub stores no per-node keys and a node only ever holds its own key. Every request and every response
carries a signed envelope (domain, node, epoch, timestamp, nonce, method, path, SHA-256 of the body):

* a request from outside the domain, with a wrong key, a revoked node or a stale epoch is rejected;
* a replayed request (same nonce) or one outside the clock-skew window is rejected;
* responses are signed in the other direction and bound to the request nonce, so a node can tell the real hub
  from an impostor and a response cannot be reflected back as a request;
* revoking a node bumps its epoch: its old key stops working everywhere at once.

All primitives are standard-library HMAC-SHA256 and ``secrets``; nothing is home-made cryptography. Transport
encryption is TLS (see ``hub.serve``); the envelope adds authentication that TLS alone does not give.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

HEADER = "X-AIPS-"
ROLES = {"client", "sandbox", "storage", "observer"}


class TrustError(PermissionError):
    """A message failed authentication. ``code`` is machine-readable (unknown_domain, bad_signature, ...)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canon(direction: str, domain: str, node: str, epoch: int, ts: float, nonce: str, method: str, path: str,
           body: bytes) -> bytes:
    return "\n".join([direction, domain, node, str(epoch), f"{ts:.3f}", nonce, method.upper(), path,
                      hashlib.sha256(body).hexdigest()]).encode()


@dataclass
class Credential:
    """What a node holds: its own key and nothing else."""

    domain: str
    node: str
    epoch: int
    key: str            # hex
    roles: list[str]
    hub: str = ""

    def sign(self, method: str, path: str, body: bytes, now: float | None = None,
             nonce: str | None = None) -> dict[str, str]:
        ts = time.time() if now is None else now
        nonce = nonce or secrets.token_hex(16)
        sig = hmac.new(bytes.fromhex(self.key),
                       _canon("req", self.domain, self.node, self.epoch, ts, nonce, method, path, body),
                       hashlib.sha256).hexdigest()
        return {f"{HEADER}Domain": self.domain, f"{HEADER}Node": self.node, f"{HEADER}Epoch": str(self.epoch),
                f"{HEADER}Ts": f"{ts:.3f}", f"{HEADER}Nonce": nonce, f"{HEADER}Sig": sig}

    def verify_response(self, request_nonce: str, status: int, body: bytes, headers: dict[str, str]) -> None:
        sig = _get(headers, "Sig")
        expect = hmac.new(bytes.fromhex(self.key),
                          _canon("resp", self.domain, self.node, self.epoch, 0.0, request_nonce, str(status), "",
                                 body), hashlib.sha256).hexdigest()
        if not sig or not hmac.compare_digest(sig, expect):
            raise TrustError("bad_response", "response is not signed by this node's trust domain (impostor hub?)")

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.__dict__, indent=2), encoding="utf-8")
        _private(p)

    @classmethod
    def load(cls, path: str | Path) -> "Credential":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class Member:
    node: str
    roles: list[str]
    epoch: int = 1
    revoked: bool = False
    issued_at: float = 0.0
    note: str = ""


@dataclass
class TrustDomain:
    """The authority. Lives only on the hub; its file must never be readable by agents or nodes."""

    domain: str
    secret: str                                     # hex, 32 bytes
    members: dict[str, Member] = field(default_factory=dict)
    skew_s: float = 30.0
    path: str | None = None

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: dict[str, float] = {}

    # -- lifecycle -----------------------------------------------------------------------------------
    @classmethod
    def create(cls, domain: str, path: str | Path | None = None) -> "TrustDomain":
        d = cls(domain=domain, secret=secrets.token_hex(32), path=str(path) if path else None)
        d.save()
        return d

    @classmethod
    def load(cls, path: str | Path) -> "TrustDomain":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        members = {k: Member(**v) for k, v in raw.pop("members", {}).items()}
        return cls(members=members, path=str(path), **raw)

    def save(self) -> None:
        if not self.path:
            return
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {"domain": self.domain, "secret": self.secret, "skew_s": self.skew_s,
                "members": {k: vars(m) for k, m in self.members.items()}}
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, p)
        _private(p)

    def _key(self, node: str, epoch: int) -> bytes:
        return hmac.new(bytes.fromhex(self.secret), f"aips-web|{self.domain}|{node}|{epoch}".encode(),
                        hashlib.sha256).digest()

    def issue(self, node: str, roles: list[str], hub: str = "", note: str = "") -> Credential:
        bad = set(roles) - ROLES
        if bad:
            raise ValueError(f"unknown role(s): {', '.join(sorted(bad))}; allowed: {', '.join(sorted(ROLES))}")
        with self._lock:
            m = self.members.get(node)
            epoch = (m.epoch + 1) if m else 1        # re-issuing always invalidates the previous credential
            self.members[node] = Member(node, sorted(set(roles)), epoch, False, time.time(), note)
            self.save()
        return Credential(self.domain, node, epoch, self._key(node, epoch).hex(), sorted(set(roles)), hub)

    def revoke(self, node: str) -> bool:
        with self._lock:
            m = self.members.get(node)
            if not m:
                return False
            m.revoked = True
            m.epoch += 1
            self.save()
        return True

    def roles(self, node: str) -> list[str]:
        m = self.members.get(node)
        return [] if not m or m.revoked else list(m.roles)

    # -- verification --------------------------------------------------------------------------------
    def verify(self, method: str, path: str, body: bytes, headers: dict[str, str],
               now: float | None = None) -> Member:
        now = time.time() if now is None else now
        domain, node = _get(headers, "Domain"), _get(headers, "Node")
        if domain != self.domain:
            raise TrustError("unknown_domain", "request is not from this trust domain")
        m = self.members.get(node or "")
        if m is None:
            raise TrustError("unknown_node", "node is not a member of this trust domain")
        if m.revoked:
            raise TrustError("revoked", f"node {node} has been revoked")
        try:
            epoch, ts = int(_get(headers, "Epoch") or -1), float(_get(headers, "Ts") or 0)
        except ValueError as exc:
            raise TrustError("malformed", "malformed envelope") from exc
        nonce, sig = _get(headers, "Nonce") or "", _get(headers, "Sig") or ""
        if epoch != m.epoch:
            raise TrustError("stale_credential", f"credential epoch {epoch} is no longer valid")
        if abs(now - ts) > self.skew_s:
            raise TrustError("clock_skew", f"timestamp outside the {self.skew_s:.0f}s window")
        if not (16 <= len(nonce) <= 64):
            raise TrustError("malformed", "bad nonce")
        expect = hmac.new(self._key(m.node, epoch), _canon("req", domain, m.node, epoch, ts, nonce, method, path, body),
                          hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            raise TrustError("bad_signature", "signature does not match (forged or tampered request)")
        with self._lock:
            cutoff = now - 2 * self.skew_s
            if len(self._nonces) > 50_000:
                self._nonces = {n: t for n, t in self._nonces.items() if t > cutoff}
            key = f"{m.node}|{nonce}"
            if key in self._nonces:
                raise TrustError("replay", "this request was already used (replay)")
            self._nonces[key] = ts
        return m

    def sign_response(self, node: str, request_nonce: str, status: int, body: bytes) -> dict[str, str]:
        m = self.members[node]
        sig = hmac.new(self._key(node, m.epoch),
                       _canon("resp", self.domain, node, m.epoch, 0.0, request_nonce, str(status), "", body),
                       hashlib.sha256).hexdigest()
        return {f"{HEADER}Sig": sig}

    def subkey(self, purpose: str) -> bytes:
        """A key for one purpose (audit ledger, storage index) derived from the domain secret."""
        return hmac.new(bytes.fromhex(self.secret), f"aips-web|purpose|{purpose}".encode(), hashlib.sha256).digest()


def _get(headers: dict[str, str], name: str) -> str | None:
    want = (HEADER + name).lower()
    for k, v in headers.items():
        if k.lower() == want:
            return v
    return None


def _private(p: Path) -> None:
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover - Windows ignores POSIX modes
        pass
