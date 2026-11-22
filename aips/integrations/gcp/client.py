"""Authenticated JSON client for Google Cloud REST APIs.

* retries 429 / 5xx with exponential backoff;
* follows ``nextPageToken`` pagination;
* polls long-running Compute Engine operations until DONE;
* the HTTP transport is injectable, so the whole integration is tested against recorded responses.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterator

from .auth import TokenProvider

COMPUTE = "https://compute.googleapis.com/compute/v1"
MONITORING = "https://monitoring.googleapis.com/v3"
LOGGING = "https://logging.googleapis.com/v2"
IAM = "https://iam.googleapis.com/v1"
SCC = "https://securitycenter.googleapis.com/v2"

Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, Any]]


class GcpError(RuntimeError):
    def __init__(self, status: int, message: str, url: str = ""):
        super().__init__(f"HTTP {status}: {message} ({url})")
        self.status = status


def urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - https Google endpoints only
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"error": {"message": raw.decode(errors="replace")[:300]}}


class GcpClient:
    def __init__(self, project: str, tokens: TokenProvider | None = None, transport: Transport | None = None,
                 retries: int = 4, sleep: Callable[[float], None] = time.sleep):
        self.project = project
        self.tokens = tokens
        self.transport = transport or urllib_transport
        self.retries = retries
        self.sleep = sleep
        self.calls: list[tuple[str, str]] = []

    # ------------------------------------------------------------------ core
    def request(self, method: str, url: str, body: Any = None, params: dict[str, Any] | None = None) -> Any:
        if not url.startswith("https://"):
            raise ValueError("Google Cloud API URLs must be HTTPS")
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        headers = {"Content-Type": "application/json", "User-Agent": "aips-gcp/1.2"}
        if self.tokens is not None:
            headers["Authorization"] = f"Bearer {self.tokens.token()}"
        data = json.dumps(body).encode() if body is not None else None
        delay = 1.0
        for attempt in range(self.retries + 1):
            self.calls.append((method, url))
            status, payload = self.transport(method, url, headers, data)
            if status in (429, 500, 502, 503, 504) and attempt < self.retries:
                self.sleep(delay)
                delay = min(delay * 2, 30)
                continue
            if status >= 400:
                msg = (payload or {}).get("error", {}).get("message", "error") if isinstance(payload, dict) else ""
                raise GcpError(status, msg, url)
            return payload
        raise GcpError(599, "retries exhausted", url)  # pragma: no cover

    def get(self, url: str, **params: Any) -> Any:
        return self.request("GET", url, params=params or None)

    def post(self, url: str, body: Any = None, **params: Any) -> Any:
        return self.request("POST", url, body if body is not None else {}, params or None)

    def patch(self, url: str, body: Any) -> Any:
        return self.request("PATCH", url, body)

    def delete(self, url: str) -> Any:
        return self.request("DELETE", url)

    def pages(self, url: str, key: str, method: str = "GET", body: dict | None = None,
              **params: Any) -> Iterator[Any]:
        token = None
        while True:
            if method == "GET":
                p = dict(params)
                if token:
                    p["pageToken"] = token
                page = self.get(url, **p)
            else:
                b = dict(body or {})
                if token:
                    b["pageToken"] = token
                page = self.post(url, b)
            items = page.get(key, [])
            if isinstance(items, dict):          # Compute aggregated lists: {"zones/x": {key: [...]}}
                yield from items.items()
            else:
                yield from items
            token = page.get("nextPageToken")
            if not token:
                return

    # ------------------------------------------------------------------ helpers
    @property
    def compute(self) -> str:
        return f"{COMPUTE}/projects/{self.project}"

    def wait(self, op: dict[str, Any], timeout_s: float = 180, poll_s: float = 2.0) -> dict[str, Any]:
        """Poll a Compute Engine operation until DONE; raise if it failed."""
        if not isinstance(op, dict) or "name" not in op or op.get("status") == "DONE":
            self._raise_op(op)
            return op
        if op.get("zone"):
            url = f"{self.compute}/zones/{op['zone'].rsplit('/', 1)[-1]}/operations/{op['name']}"
        elif op.get("region"):
            url = f"{self.compute}/regions/{op['region'].rsplit('/', 1)[-1]}/operations/{op['name']}"
        else:
            url = f"{self.compute}/global/operations/{op['name']}"
        deadline = time.monotonic() + timeout_s
        while True:
            cur = self.get(url)
            if cur.get("status") == "DONE":
                self._raise_op(cur)
                return cur
            if time.monotonic() > deadline:
                raise GcpError(504, f"operation {op['name']} did not finish in {timeout_s:.0f}s", url)
            self.sleep(poll_s)

    @staticmethod
    def _raise_op(op: Any) -> None:
        if isinstance(op, dict) and op.get("error"):
            errs = op["error"].get("errors", [])
            raise GcpError(400, "; ".join(e.get("message", "") for e in errs) or "operation failed")
