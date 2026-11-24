"""Human-only approvals that an AI agent cannot fake.

The human's passphrase is never stored. Only a salted PBKDF2 verifier is on disk, so an agent that reads every
file on the machine still cannot produce an approval. When the human unlocks the hub, the derived key lives in
the hub's memory only. An approval is an HMAC over (request id, SHA-256 of the exact action, expiry):

* it approves *that* action only; changing one character of the command invalidates it;
* it expires (default 10 minutes) and can be used once;
* a wrong passphrase only slows the next attempt (capped back-off), it never locks the real human out;
* a one-time recovery code, shown once at setup, resets the passphrase if it is forgotten.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ITERATIONS = 240_000
MAX_BACKOFF_S = 30.0


class ApprovalError(PermissionError):
    pass


def action_digest(action: str) -> str:
    return hashlib.sha256(action.encode()).hexdigest()


@dataclass
class _State:
    salt: str
    verifier: str
    recovery: str          # SHA-256 of the recovery code
    iterations: int = ITERATIONS
    failures: int = 0
    next_try: float = 0.0


class HumanLock:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._key: bytes | None = None
        self._used: set[str] = set()
        self.state: _State | None = (_State(**json.loads(self.path.read_text(encoding="utf-8")))
                                     if self.path.exists() else None)

    # -- setup ---------------------------------------------------------------------------------------
    @staticmethod
    def _derive(passphrase: str, salt: str, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), bytes.fromhex(salt), iterations)

    def setup(self, passphrase: str) -> str:
        """Set the passphrase. Returns a one-time recovery code to show the human once."""
        if len(passphrase) < 10:
            raise ValueError("use a passphrase of at least 10 characters")
        salt = secrets.token_hex(16)
        key = self._derive(passphrase, salt, ITERATIONS)
        recovery = "-".join(secrets.token_hex(3) for _ in range(4))
        self.state = _State(salt, hmac.new(key, b"verifier", hashlib.sha256).hexdigest(),
                            hashlib.sha256(recovery.encode()).hexdigest())
        self._save()
        return recovery

    def reset_with_recovery(self, recovery: str, new_passphrase: str) -> str:
        if not self.state or not hmac.compare_digest(hashlib.sha256(recovery.strip().encode()).hexdigest(),
                                                     self.state.recovery):
            raise ApprovalError("recovery code is not valid")
        self._key = None
        return self.setup(new_passphrase)

    def _save(self) -> None:
        assert self.state is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(vars(self.state)), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover
            pass

    # -- unlocking -----------------------------------------------------------------------------------
    def check(self, passphrase: str, now: float | None = None) -> bytes:
        """Return the key for a correct passphrase. A wrong one costs a short, capped wait - never a lockout."""
        if not self.state:
            raise ApprovalError("no human passphrase is set up; run: aips web init")
        now = time.time() if now is None else now
        with self._lock:
            if now < self.state.next_try:
                raise ApprovalError(f"too many wrong passphrases; try again in {self.state.next_try - now:.0f}s")
            key = self._derive(passphrase, self.state.salt, self.state.iterations)
            if not hmac.compare_digest(hmac.new(key, b"verifier", hashlib.sha256).hexdigest(), self.state.verifier):
                self.state.failures += 1
                self.state.next_try = now + min(MAX_BACKOFF_S, 2.0 ** min(self.state.failures, 6) / 4)
                self._save()
                raise ApprovalError("wrong passphrase")
            if self.state.failures:
                self.state.failures, self.state.next_try = 0, 0.0
                self._save()
            return key

    def unlock(self, passphrase: str, now: float | None = None) -> None:
        self._key = self.check(passphrase, now)

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def lock(self) -> None:
        self._key = None

    # -- approvals -----------------------------------------------------------------------------------
    @staticmethod
    def make_token(key: bytes, request_id: str, action: str, ttl_s: float = 600.0, now: float | None = None) -> str:
        exp = int((time.time() if now is None else now) + ttl_s)
        mac = hmac.new(key, f"approve|{request_id}|{action_digest(action)}|{exp}".encode(), hashlib.sha256)
        return f"{request_id}.{exp}.{mac.hexdigest()}"

    def approve(self, passphrase: str, request_id: str, action: str, ttl_s: float = 600.0,
                now: float | None = None) -> str:
        """What the human runs: proves knowledge of the passphrase for exactly this action."""
        return self.make_token(self.check(passphrase, now), request_id, action, ttl_s, now)

    def verify(self, token: str, request_id: str, action: str, now: float | None = None) -> None:
        if self._key is None:
            raise ApprovalError("the hub is locked: a human must unlock it before approvals can be accepted")
        now = time.time() if now is None else now
        try:
            rid, exp_s, mac = token.split(".")
            exp = int(exp_s)
        except ValueError as exc:
            raise ApprovalError("malformed approval") from exc
        if rid != request_id:
            raise ApprovalError("approval is for a different request")
        if now > exp:
            raise ApprovalError("approval has expired")
        expect = hmac.new(self._key, f"approve|{request_id}|{action_digest(action)}|{exp}".encode(),
                          hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expect):
            raise ApprovalError("approval signature is not valid (not made with the human's passphrase, "
                                "or the action changed)")
        with self._lock:
            if token in self._used:
                raise ApprovalError("approval was already used")
            self._used.add(token)
