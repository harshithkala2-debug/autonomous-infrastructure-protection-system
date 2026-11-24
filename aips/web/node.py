"""A machine in the AIPS web.

A node holds one credential (its own key only), connects *out* to the hub, sends signed heartbeats with its
telemetry, pulls jobs for its roles and verifies that every response really comes from its trust domain:

* ``sandbox`` - runs jobs in its own :class:`LocalSandbox` (low integrity + Job Object on Windows, rlimits and a
  network namespace on Linux) and returns the result;
* ``storage`` - keeps write-once replicas of protected objects and serves them back for repairs;
* ``client``  - can store and fetch objects and submit sandbox jobs (an AIPS instance, an agent host, a CLI).
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from ..agents.sandbox import LocalSandbox, SandboxLimits
from ..backup.store import IntegrityError, ObjectStore
from .trust import Credential, TrustError


class WebClient:
    def __init__(self, cred: Credential, hub_url: str | None = None, cafile: str | None = None,
                 timeout: float = 30.0):
        self.cred = cred
        self.hub = (hub_url or cred.hub).rstrip("/")
        self.timeout = timeout
        self._ctx = ssl.create_default_context(cafile=cafile) if self.hub.startswith("https") else None

    def call(self, path: str, body: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        raw = json.dumps(body or {}).encode()
        headers = self.cred.sign("POST", path, raw)
        req = urllib.request.Request(self.hub + path, data=raw, method="POST",
                                     headers={**headers, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout, context=self._ctx) as r:
                status, data, rh = r.status, r.read(), dict(r.headers.items())
        except urllib.error.HTTPError as e:
            status, data, rh = e.code, e.read(), dict(e.headers.items())
        if status == 401:
            raise TrustError(json.loads(data or b"{}").get("error", "unauthorised"),
                             "the hub rejected this node's credential")
        self.cred.verify_response(headers["X-AIPS-Nonce"], status, data, rh)
        payload = json.loads(data or b"null")
        if status >= 400:
            raise RuntimeError(f"hub refused {path}: {payload.get('error') if isinstance(payload, dict) else payload}")
        return payload

    # convenience for clients
    def put(self, name: str, data: bytes) -> Any:
        return self.call("/web/storage/put", {"name": name, "data": base64.b64encode(data).decode()})

    def get(self, name: str, version: int | None = None) -> tuple[dict[str, Any], bytes]:
        r = self.call("/web/storage/get", {"name": name, "version": version})
        return r, base64.b64decode(r.pop("data"))

    def sandbox(self, command: str, files: dict[str, bytes] | None = None, timeout: float = 300.0) -> Any:
        return self.call("/web/sandbox/run", {"command": command, "timeout": timeout,
                                              "files": {k: base64.b64encode(v).decode()
                                                        for k, v in (files or {}).items()}},
                         timeout=timeout + 10)

    def status(self) -> Any:
        return self.call("/web/status")


_LAST_CPU: list[tuple[int, int]] = []


def _win_metrics(m: dict[str, float]) -> None:
    import ctypes
    from ctypes import wintypes as w

    k32 = ctypes.windll.kernel32
    idle, kern, user = w.FILETIME(), w.FILETIME(), w.FILETIME()
    if k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user)):
        to = lambda ft: (ft.dwHighDateTime << 32) | ft.dwLowDateTime  # noqa: E731
        busy, total = to(kern) + to(user) - to(idle), to(kern) + to(user)
        if _LAST_CPU:
            db, dt = busy - _LAST_CPU[0][0], total - _LAST_CPU[0][1]
            m["cpu"] = round(100.0 * db / dt, 1) if dt > 0 else 0.0
        _LAST_CPU[:] = [(busy, total)]

    class MS(ctypes.Structure):
        _fields_ = [("dwLength", w.DWORD), ("dwMemoryLoad", w.DWORD)] + [(f"x{i}", ctypes.c_ulonglong)
                                                                          for i in range(7)]
    ms = MS()
    ms.dwLength = ctypes.sizeof(ms)
    if k32.GlobalMemoryStatusEx(ctypes.byref(ms)):
        m["memory"] = float(ms.dwMemoryLoad)
    arr, needed = (w.DWORD * 4096)(), w.DWORD()
    if ctypes.windll.psapi.EnumProcesses(ctypes.byref(arr), ctypes.sizeof(arr), ctypes.byref(needed)):
        m["processes"] = float(needed.value // ctypes.sizeof(w.DWORD))


def _metrics(running: int, errors: int) -> dict[str, float]:
    """Real host telemetry: CPU %, memory %, process count, plus the node's own job and error counts."""
    m = {"cpu": 0.0, "memory": 0.0, "processes": 0.0, "jobs_running": float(running), "errors": float(errors),
         "net_kbps": 0.0}
    try:
        if os.name == "nt":
            _win_metrics(m)
        else:
            m["cpu"] = round(os.getloadavg()[0] * 100 / (os.cpu_count() or 1), 1)
            if Path("/proc/meminfo").exists():
                info = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines()
                            if ":" in line)
                tot, avail = (float(info[k].split()[0]) for k in ("MemTotal", "MemAvailable"))
                m["memory"] = round(100 * (1 - avail / tot), 1)
                m["processes"] = float(sum(1 for d in Path("/proc").iterdir() if d.name.isdigit()))
    except Exception:  # noqa: BLE001 - telemetry is best effort, never fatal
        pass
    return m


class WebNode:
    def __init__(self, cred: Credential, state_dir: str | Path, hub_url: str | None = None,
                 cafile: str | None = None, limits: SandboxLimits | None = None,
                 metrics: Callable[[], dict[str, float]] | None = None):
        self.cred = cred
        self.client = WebClient(cred, hub_url, cafile)
        self.state = Path(state_dir)
        self.sandbox = LocalSandbox(self.state / "sandbox", limits) if "sandbox" in cred.roles else None
        self.replicas = ObjectStore(self.state / "replicas", worm=True) if "storage" in cred.roles else None
        self.metrics_fn = metrics
        self.running = 0
        self.errors = 0
        self.stopped = threading.Event()
        self.handled: list[str] = []

    def heartbeat(self) -> Any:
        m = self.metrics_fn() if self.metrics_fn else _metrics(self.running, self.errors)
        return self.client.call("/web/heartbeat", {"metrics": m})

    def execute(self, job: dict[str, Any]) -> Any:
        p = job["payload"]
        if job["type"] == "sandbox" and self.sandbox is not None:
            lim = SandboxLimits(**{k: v for k, v in (p.get("limits") or {}).items()
                                   if k in SandboxLimits.__dataclass_fields__})
            files = {k: base64.b64decode(v) for k, v in (p.get("files") or {}).items()}
            res = self.sandbox.run(p["command"], files=files, limits=lim)
            out = res.to_dict()
            out["node"] = self.cred.node
            self.sandbox.cleanup(res.job_id)
            return out
        if job["type"] == "replicate" and self.replicas is not None:
            data = base64.b64decode(p["data"])
            digest = self.replicas.put(data)
            return {"stored": digest == p["digest"], "digest": digest}
        if job["type"] == "fetch" and self.replicas is not None:
            try:
                return {"data": base64.b64encode(self.replicas.get(p["digest"])).decode()}
            except IntegrityError as exc:
                return {"error": str(exc)}
        return {"error": f"this node cannot run {job['type']} jobs"}

    def step(self) -> str | None:
        """One heartbeat + one job. Returns the job id handled, if any."""
        self.heartbeat()
        job = self.client.call("/web/poll").get("job")
        if not job:
            return None
        self.running += 1
        try:
            result = self.execute(job)
        except Exception as exc:  # noqa: BLE001 - report, never crash the node
            self.errors += 1
            result = {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            self.running -= 1
        self.client.call("/web/result", {"job_id": job["id"], "result": result})
        self.handled.append(job["id"])
        return job["id"]

    def run_forever(self, interval: float = 2.0) -> None:
        while not self.stopped.is_set():
            try:
                if self.step() is None:
                    self.stopped.wait(interval)
            except TrustError:
                raise                                   # revoked or impostor hub: stop, a human must look
            except (OSError, RuntimeError):
                self.errors += 1
                self.stopped.wait(interval * 2)

    def start(self, interval: float = 0.5) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, args=(interval,), daemon=True, name=f"aips-node-{self.cred.node}")
        t.start()
        return t

    def stop(self) -> None:
        self.stopped.set()
