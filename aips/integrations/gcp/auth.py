"""Google Cloud access tokens without the Google SDKs.

Tried in order (``default_token_provider``):

1. ``AIPS_GCP_ACCESS_TOKEN`` environment variable (short-lived token, e.g. from Cloud Shell);
2. a service-account key file named by ``GOOGLE_APPLICATION_CREDENTIALS`` (signed JWT, needs the optional
   ``cryptography`` package);
3. the ``gcloud`` CLI (``gcloud auth print-access-token``);
4. the Compute Engine metadata server - the recommended setup: run AIPS on a small VM whose service account
   has only the roles AIPS needs, and no key file exists anywhere.

Tokens are cached until shortly before they expire.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Callable

SCOPE = "https://www.googleapis.com/auth/cloud-platform"
METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
TOKEN_URL = "https://oauth2.googleapis.com/token"


class AuthError(RuntimeError):
    pass


class TokenProvider:
    name = "token"

    def __init__(self) -> None:
        self._token: str | None = None
        self._expiry = 0.0

    def _fetch(self) -> tuple[str, float]:  # pragma: no cover - interface
        raise NotImplementedError

    def token(self) -> str:
        if self._token is None or time.time() > self._expiry - 120:
            self._token, ttl = self._fetch()
            self._expiry = time.time() + ttl
        return self._token


class StaticToken(TokenProvider):
    name = "env"

    def __init__(self, token: str):
        super().__init__()
        self._static = token

    def _fetch(self) -> tuple[str, float]:
        return self._static, 3000


class MetadataToken(TokenProvider):
    name = "metadata"

    def __init__(self, timeout: float = 2.0):
        super().__init__()
        self.timeout = timeout

    def _fetch(self) -> tuple[str, float]:
        req = urllib.request.Request(METADATA_URL, headers={"Metadata-Flavor": "Google"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - fixed internal URL
                d = json.loads(r.read())
        except OSError as exc:
            raise AuthError(f"metadata server unavailable: {exc}") from exc
        return d["access_token"], float(d.get("expires_in", 3000))


class GcloudToken(TokenProvider):
    name = "gcloud"

    def __init__(self, runner: Callable[..., subprocess.CompletedProcess] | None = None):
        super().__init__()
        self.runner = runner or subprocess.run

    def _fetch(self) -> tuple[str, float]:
        exe = shutil.which("gcloud") or shutil.which("gcloud.cmd")
        if not exe:
            raise AuthError("gcloud CLI not found")
        try:
            cp = self.runner([exe, "auth", "print-access-token"], capture_output=True, text=True, timeout=30,
                             check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AuthError(f"gcloud did not return a token: {exc}") from exc
        if cp.returncode != 0 or not cp.stdout.strip():
            raise AuthError(f"gcloud auth print-access-token failed: {cp.stderr.strip()[:200]}")
        return cp.stdout.strip(), 3000


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class ServiceAccountKeyToken(TokenProvider):
    name = "service-account-key"

    def __init__(self, key_path: str):
        super().__init__()
        self.key = json.loads(open(key_path, encoding="utf-8").read())

    def assertion(self, now: float | None = None) -> str:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise AuthError("service-account keys need: pip install 'aips[crypto]'") from exc
        now = int(now or time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": self.key.get("private_key_id", "")}
        claims = {"iss": self.key["client_email"], "scope": SCOPE, "aud": TOKEN_URL, "iat": now, "exp": now + 3600}
        signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}".encode()
        pk = serialization.load_pem_private_key(self.key["private_key"].encode(), password=None)
        sig = pk.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input.decode()}.{_b64(sig)}"

    def _fetch(self) -> tuple[str, float]:
        body = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                       "assertion": self.assertion()}).encode()
        req = urllib.request.Request(TOKEN_URL, data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 - fixed https URL
                d = json.loads(r.read())
        except OSError as exc:
            raise AuthError(f"token exchange failed: {exc}") from exc
        return d["access_token"], float(d.get("expires_in", 3000))


class ChainToken(TokenProvider):
    name = "chain"

    def __init__(self, providers: list[TokenProvider]):
        super().__init__()
        self.providers = providers
        self.used: str | None = None

    def _fetch(self) -> tuple[str, float]:
        errors = []
        for p in self.providers:
            try:
                tok = p.token()
                self.used = p.name
                return tok, max(60.0, p._expiry - time.time())
            except (AuthError, OSError, KeyError, ValueError) as exc:
                errors.append(f"{p.name}: {exc}")
        raise AuthError("no Google Cloud credentials found (" + "; ".join(errors) + ")")


def default_token_provider() -> ChainToken:
    providers: list[TokenProvider] = []
    if os.environ.get("AIPS_GCP_ACCESS_TOKEN"):
        providers.append(StaticToken(os.environ["AIPS_GCP_ACCESS_TOKEN"]))
    key = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if key and os.path.exists(key):
        providers.append(ServiceAccountKeyToken(key))
    providers += [GcloudToken(), MetadataToken()]
    return ChainToken(providers)
