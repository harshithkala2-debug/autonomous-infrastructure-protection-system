"""The AIPS web hub: the orchestrator every protected machine connects to.

Topology is a star inside one closed trust domain. Nodes connect *out* to the hub (so a node behind NAT or in a
cloud VPC needs no open ports) and pull work. The hub:

* authenticates every request with the trust domain and signs every response;
* keeps a registry of nodes (roles, last heartbeat, telemetry) and scores telemetry with an Isolation Forest;
* routes sandbox jobs to the least-loaded sandbox node, with leases: a job whose node goes silent is moved to
  another node, and a node that answers for a job it does not hold is quarantined;
* keeps protected storage, replicates every object to ``replication`` storage nodes and repairs a corrupted
  local copy from a replica (a replica that returns wrong data is quarantined);
* turns intrusions (forged / replayed / revoked requests), quarantines and anomalies into AIPS findings;
* accepts human approvals only with a token made from the human's passphrase (see :mod:`aips.web.human`).

Everything the hub accepts, rejects or decides is written to a tamper-evident audit ledger.
"""

from __future__ import annotations

import base64
import json
import logging
import ssl
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from ..agents.sandbox import SandboxResult
from ..backup.store import IntegrityError
from ..core.audit import AuditLedger
from ..core.models import Category, Evidence, Finding, Severity
from ..ml.isolation import IsolationForest
from .human import ApprovalError, HumanLock
from .storage import ProtectedStore, RetentionLocked
from .trust import TrustDomain, TrustError

log = logging.getLogger("aips.web")
METRICS = ("cpu", "memory", "processes", "jobs_running", "errors", "net_kbps")
MAX_BODY = 64 * 1024 * 1024


@dataclass
class NodeInfo:
    node: str
    roles: list[str]
    last_seen: float = 0.0
    addr: str = ""
    metrics: dict[str, float] = field(default_factory=dict)
    history: deque = field(default_factory=lambda: deque(maxlen=500))
    running: int = 0
    anomaly: float = 0.0
    quarantined: str = ""


@dataclass
class Job:
    id: str
    type: str                      # sandbox | replicate | fetch
    role: str
    payload: dict[str, Any]
    created: float
    status: str = "queued"         # queued | leased | done | failed
    node: str = ""
    lease_until: float = 0.0
    attempts: int = 0
    result: Any = None
    target: str = ""               # a specific node (replicate / fetch), or "" for any
    exclude: set[str] = field(default_factory=set)
    done: threading.Event = field(default_factory=threading.Event)


class WebHub:
    def __init__(self, domain: TrustDomain, state_dir: str | Path, human: HumanLock | None = None,
                 replication: int = 2, lease_s: float = 60.0, offline_s: float = 30.0,
                 on_finding: Callable[[Finding], None] | None = None, clock: Callable[[], float] = time.time,
                 retention_s: float = 7 * 86400, anomaly_threshold: float = 0.68):
        self.domain = domain
        self.state = Path(state_dir)
        self.state.mkdir(parents=True, exist_ok=True)
        self.human = human or HumanLock(self.state / "human.json")
        self.audit = AuditLedger(self.state / "web-audit.jsonl", key=domain.subkey("audit"))
        self.store = ProtectedStore(self.state / "storage", domain.subkey("storage-index"), retention_s=retention_s)
        self.replication = replication
        self.lease_s = lease_s
        self.offline_s = offline_s
        self.on_finding = on_finding
        self.clock = clock
        self.anomaly_threshold = anomaly_threshold
        self.nodes: dict[str, NodeInfo] = {}
        self.jobs: dict[str, Job] = {}
        self.replicas: dict[str, set[str]] = defaultdict(set)        # digest -> nodes that confirmed a copy
        self.approvals: dict[str, dict[str, Any]] = {}
        self.findings: list[Finding] = []
        self.rejections: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.counters: dict[str, int] = defaultdict(int)
        self._lock = threading.RLock()
        self._forest: IsolationForest | None = None
        self._forest_n = 0
        self._ranges: list[tuple[float, float]] = []

    # ===================================================================================== findings
    def _finding(self, signal: str, severity: Severity, title: str, asset: str, detail: dict[str, Any],
                 category: Category = Category.SECURITY, confidence: float = 0.9) -> Finding:
        now = self.clock()
        f = Finding(detector="web.hub", category=category, severity=severity, confidence=confidence, asset_id=asset,
                    title=title, description=json.dumps(detail, default=str)[:1500], created_at=now, signal=signal,
                    tags={"key": asset}, evidence=[Evidence("web", "web.hub", detail, now)])
        self.findings.append(f)
        self.audit.append("web.hub", f"finding.{signal}", {"asset": asset, "title": title, **detail})
        if self.on_finding:
            self.on_finding(f)
        return f

    def _reject(self, ip: str, code: str, path: str, node: str | None) -> None:
        now = self.clock()
        q = self.rejections[ip]
        q.append(now)
        self.counters[f"rejected_{code}"] += 1
        self.audit.append("web.hub", "request.rejected", {"code": code, "path": path, "claimed_node": node or "",
                                                          "source": ip})
        recent = [t for t in q if t > now - 60]
        if code in ("bad_signature", "replay", "revoked", "stale_credential", "unknown_domain") or len(recent) == 5:
            sev = Severity.HIGH if code in ("replay", "revoked", "bad_signature") else Severity.MEDIUM
            self._finding("web_intrusion", sev, f"rejected {code} request to the AIPS web from {ip}",
                          f"web:{node or ip}", {"code": code, "path": path, "source": ip, "claimed_node": node or "",
                                                "recent_rejections": len(recent)})

    def quarantine(self, node: str, reason: str) -> None:
        with self._lock:
            info = self.nodes.get(node)
            if info and info.quarantined:
                return
            self.domain.revoke(node)
            if info:
                info.quarantined = reason
            for job in self.jobs.values():
                if job.node == node and job.status == "leased":
                    self._requeue(job, f"node {node} quarantined")
            for holders in self.replicas.values():
                holders.discard(node)
        self._finding("web_node_quarantined", Severity.HIGH, f"node {node} quarantined: {reason}", f"web:{node}",
                      {"node": node, "reason": reason})

    # ===================================================================================== registry / telemetry
    def heartbeat(self, node: str, roles: list[str], metrics: dict[str, Any], addr: str) -> dict[str, Any]:
        now = self.clock()
        with self._lock:
            info = self.nodes.get(node) or NodeInfo(node, roles)
            info.roles, info.last_seen, info.addr = roles, now, addr
            info.metrics = {k: float(metrics.get(k, 0.0)) for k in METRICS}
            vec = [info.metrics[k] for k in METRICS]
            info.history.append(vec)
            self.nodes[node] = info
            self._score(info, vec)
        return {"ok": True, "time": now}

    def _score(self, info: NodeInfo, vec: list[float]) -> None:
        pool = [v for n in self.nodes.values() for v in list(n.history)[:-1]] if len(info.history) > 1 else []
        if len(pool) < 40:
            return
        if self._forest is None or len(pool) - self._forest_n >= 100:
            self._forest = IsolationForest(n_trees=60, sample_size=128).fit(pool[-1500:])
            self._forest_n = len(pool)
            cols = list(zip(*pool[-1500:]))
            self._ranges = [(min(c), max(c)) for c in cols]
        score = self._forest.score(vec)
        # Isolation Forest cannot split a feature that never varied in training (e.g. errors always 0);
        # a value far outside every value ever seen is then reported directly.
        far = [METRICS[i] for i, (x, (lo, hi)) in enumerate(zip(vec, self._ranges))
               if x > hi + max(5.0, (hi - lo)) * 2 or x < lo - max(5.0, (hi - lo)) * 2]
        if len(far) >= 2:
            score = max(score, 0.8)
        info.anomaly = score
        if info.anomaly >= self.anomaly_threshold:
            self._finding("web_node_anomaly", Severity.MEDIUM,
                          f"node {info.node} telemetry is unusual (score {info.anomaly:.2f})",
                          f"web:{info.node}", {"node": info.node, "score": info.anomaly, "metrics": info.metrics,
                                               "far_outside_history": far},
                          category=Category.SECURITY, confidence=min(0.9, info.anomaly))

    def tick(self) -> dict[str, Any]:
        """Expire leases and mark silent nodes. Call every few seconds."""
        now = self.clock()
        moved = 0
        with self._lock:
            for job in self.jobs.values():
                if job.status == "leased" and now > job.lease_until:
                    self._requeue(job, f"lease expired on {job.node}")
                    moved += 1
            offline = [n.node for n in self.nodes.values() if now - n.last_seen > self.offline_s]
        return {"requeued": moved, "offline": offline}

    def _requeue(self, job: Job, why: str) -> None:
        self.audit.append("web.hub", "job.requeued", {"job": job.id, "from": job.node, "why": why})
        job.exclude.add(job.node)
        job.status, job.node, job.lease_until = "queued", "", 0.0
        if job.attempts >= 3:
            job.status, job.result = "failed", {"error": f"gave up after {job.attempts} attempts ({why})"}
            job.done.set()

    def online(self, role: str) -> list[NodeInfo]:
        now = self.clock()
        return [n for n in self.nodes.values() if role in n.roles and not n.quarantined
                and now - n.last_seen <= self.offline_s and self.domain.roles(n.node)]

    # ===================================================================================== jobs
    def submit(self, type_: str, role: str, payload: dict[str, Any], target: str = "") -> Job:
        job = Job(uuid.uuid4().hex[:16], type_, role, payload, self.clock(), target=target)
        with self._lock:
            self.jobs[job.id] = job
        self.audit.append("web.hub", "job.submitted", {"job": job.id, "type": type_, "target": target})
        return job

    def poll(self, node: str) -> dict[str, Any] | None:
        now = self.clock()
        with self._lock:
            info = self.nodes.get(node)
            roles = set(self.domain.roles(node))
            for job in sorted(self.jobs.values(), key=lambda j: j.created):
                if job.status != "queued" or job.role not in roles or node in job.exclude:
                    continue
                if job.target and job.target != node:
                    continue
                if job.type == "sandbox" and info is not None:
                    # least-loaded routing: leave the job for an idler sandbox node if there is one
                    idler = [n for n in self.online("sandbox") if n.running < info.running and n.node not in job.exclude]
                    if idler:
                        continue
                job.status, job.node, job.lease_until = "leased", node, now + self.lease_s
                job.attempts += 1
                if info is not None:
                    info.running += 1
                return {"id": job.id, "type": job.type, "payload": job.payload}
        return None

    def complete(self, node: str, job_id: str, result: Any) -> dict[str, Any]:
        with self._lock:
            job = self.jobs.get(job_id)
            if job is None or job.status != "leased" or job.node != node:
                held_by = job.node if job else ""
                self.audit.append("web.hub", "job.forged_result", {"job": job_id, "node": node, "held_by": held_by})
                bad = True
            else:
                bad = False
                info = self.nodes.get(node)
                if info is not None:
                    info.running = max(0, info.running - 1)
        if bad:
            self.quarantine(node, f"sent a result for job {job_id} it was not assigned (forged result)")
            return {"ok": False}
        if job.type == "replicate" and isinstance(result, dict) and result.get("stored"):
            if result.get("digest") == job.payload["digest"]:
                self.replicas[job.payload["digest"]].add(node)
        job.status, job.result = "done", result
        self.audit.append("web.hub", "job.done", {"job": job.id, "type": job.type, "node": node})
        job.done.set()
        return {"ok": True}

    def wait(self, job: Job, timeout: float) -> Any:
        if not job.done.wait(timeout):
            raise TimeoutError(f"job {job.id} did not finish in {timeout:.0f}s")
        if job.status == "failed":
            raise RuntimeError(job.result.get("error", "job failed"))
        return job.result

    def remote_sandbox(self, request: dict[str, Any], timeout: float = 300.0) -> SandboxResult:
        """Run a command on a sandbox node (the ``remote`` callable of :class:`HybridSandbox`)."""
        if not self.online("sandbox"):
            raise RuntimeError("no sandbox node is online")
        payload = {"command": request["command"], "limits": request.get("limits", {}), "agent": request.get("agent"),
                   "files": {k: base64.b64encode(v).decode() for k, v in request.get("files", {}).items()}}
        job = self.submit("sandbox", "sandbox", payload)
        res = SandboxResult.from_dict(self.wait(job, timeout))
        res.node = job.node
        return res

    # ===================================================================================== storage
    def storage_put(self, name: str, data: bytes, by: str) -> dict[str, Any]:
        v = self.store.put(name, data, by, self.clock())
        targets = [n.node for n in self.online("storage")][: self.replication]
        for t in targets:
            self.submit("replicate", "storage", {"digest": v.digest, "data": base64.b64encode(data).decode()},
                        target=t)
        return {"name": name, "version": v.version, "digest": v.digest, "size": v.size, "replicating_to": targets}

    def storage_get(self, name: str, version: int | None = None, timeout: float = 10.0) -> tuple[dict[str, Any], bytes]:
        try:
            v, data = self.store.get(name, version)
            return {"name": name, "version": v.version, "digest": v.digest, "repaired": False}, data
        except IntegrityError as exc:
            vs = self.store.versions(name)
            if not vs or "index" in str(exc):
                raise
            v = vs[-1] if version is None else next(x for x in vs if x.version == version)
        data = self._repair(v.digest, timeout)
        return {"name": name, "version": v.version, "digest": v.digest, "repaired": True}, data

    def _repair(self, digest: str, timeout: float) -> bytes:
        self._finding("storage_corruption", Severity.HIGH, f"stored object {digest[:12]} failed its integrity check",
                      "web:storage", {"digest": digest}, category=Category.DATA_INTEGRITY)
        holders = [n for n in self.replicas.get(digest, set()) if n in {x.node for x in self.online("storage")}]
        for node in holders:
            job = self.submit("fetch", "storage", {"digest": digest}, target=node)
            try:
                res = self.wait(job, timeout)
            except (TimeoutError, RuntimeError):
                continue
            if not isinstance(res, dict) or "data" not in res:
                # an honest "my copy is bad too" is not a lie: try the next replica
                self.audit.append("web.hub", "storage.replica_unavailable", {"digest": digest, "node": node,
                                                                             "detail": str(res)[:200]})
                continue
            data = base64.b64decode(res["data"])
            try:
                self.store.repair(digest, data)
            except IntegrityError:
                self.quarantine(node, f"returned a replica of {digest[:12]} with the wrong content")
                continue
            self.audit.append("web.hub", "storage.repaired", {"digest": digest, "from": node})
            return data
        raise IntegrityError(f"object {digest[:12]} is corrupted and no healthy replica answered")

    # ===================================================================================== human approvals
    def request_approval(self, kind: str, action: str, payload: dict[str, Any] | None = None) -> str:
        rid = uuid.uuid4().hex[:12]
        with self._lock:
            self.approvals[rid] = {"id": rid, "kind": kind, "action": action, "payload": payload or {},
                                   "created": self.clock(), "status": "pending"}
        self.audit.append("web.hub", "approval.requested", {"id": rid, "kind": kind, "action": action})
        return rid

    def approve(self, request_id: str, token: str) -> dict[str, Any]:
        req = self.approvals.get(request_id)
        if req is None or req["status"] != "pending":
            raise ApprovalError("no such pending request")
        try:
            self.human.verify(token, request_id, req["action"], self.clock())
        except ApprovalError as exc:
            self.audit.append("web.hub", "approval.refused", {"id": request_id, "why": str(exc)})
            self._finding("web_fake_approval", Severity.HIGH, f"invalid approval for {req['kind']} was refused",
                          "web:approvals", {"id": request_id, "kind": req["kind"], "why": str(exc)})
            raise
        req["status"] = "approved"
        out = self._execute(req)
        self.audit.append("human", "approval.granted", {"id": request_id, "kind": req["kind"], "result": out})
        return out

    def _execute(self, req: dict[str, Any]) -> dict[str, Any]:
        kind, p = req["kind"], req["payload"]
        if kind == "storage.delete":
            try:
                self.store.delete(p["name"], "human", self.clock())
                return {"deleted": p["name"]}
            except RetentionLocked as exc:
                return {"error": str(exc)}
        if kind == "node.readmit":
            with self._lock:
                info = self.nodes.get(p["node"])
                if info:
                    info.quarantined = ""
            return {"readmitted": p["node"], "note": "issue a fresh credential with: aips web issue"}
        if kind == "custom":
            return {"approved": req["action"]}
        return {"error": f"unknown approval kind {kind}"}

    # ===================================================================================== status
    def status(self) -> dict[str, Any]:
        now = self.clock()
        with self._lock:
            nodes = [{"node": n.node, "roles": n.roles, "online": now - n.last_seen <= self.offline_s,
                      "last_seen_s": round(now - n.last_seen, 1), "running": n.running, "anomaly": n.anomaly,
                      "quarantined": n.quarantined, "metrics": n.metrics} for n in self.nodes.values()]
            jobs: dict[str, int] = defaultdict(int)
            for j in self.jobs.values():
                jobs[j.status] += 1
        ok, _, why = self.audit.verify()
        return {"domain": self.domain.domain, "nodes": nodes, "jobs": dict(jobs), "storage": self.store.verify(),
                "human_unlocked": self.human.unlocked, "audit": why if ok else f"BROKEN: {why}",
                "findings": len(self.findings), "counters": dict(self.counters),
                "pending_approvals": [a for a in self.approvals.values() if a["status"] == "pending"]}

    # ===================================================================================== HTTP
    def handle(self, method: str, path: str, body: bytes, headers: dict[str, str], ip: str) -> tuple[int, Any, str]:
        """Return (status, payload, node). ``node`` is "" for unauthenticated (human) routes."""
        if path in ("/web/approve", "/web/approvals"):
            if ip not in ("127.0.0.1", "::1"):
                return 403, {"error": "approvals are accepted on the hub machine only"}, ""
            if path == "/web/approvals":
                return 200, [a for a in self.approvals.values() if a["status"] == "pending"], ""
            b = json.loads(body or b"{}")
            try:
                return 200, self.approve(str(b.get("request_id")), str(b.get("token"))), ""
            except ApprovalError as exc:
                return 403, {"error": str(exc)}, ""
        try:
            m = self.domain.verify(method, path, body, headers, self.clock())
        except TrustError as exc:
            claimed = next((v for k, v in headers.items() if k.lower() == "x-aips-node"), None)
            self._reject(ip, exc.code, path, claimed)
            return 401, {"error": exc.code}, ""
        node = m.node
        b = json.loads(body or b"{}")
        roles = set(m.roles)

        def need(role: str) -> None:
            if role not in roles:
                raise PermissionError(f"node {node} lacks role {role}")

        try:
            if path == "/web/heartbeat":
                return 200, self.heartbeat(node, sorted(roles), b.get("metrics", {}), ip), node
            if path == "/web/poll":
                return 200, {"job": self.poll(node)}, node
            if path == "/web/result":
                return 200, self.complete(node, str(b.get("job_id")), b.get("result")), node
            if path == "/web/status":
                return 200, self.status(), node
            if path == "/web/storage/put":
                need("client")
                return 200, self.storage_put(str(b["name"]), base64.b64decode(b["data"]), node), node
            if path == "/web/storage/get":
                need("client")
                meta, data = self.storage_get(str(b["name"]), b.get("version"))
                return 200, {**meta, "data": base64.b64encode(data).decode()}, node
            if path == "/web/sandbox/run":
                need("client")
                files = {k: base64.b64decode(v) for k, v in b.get("files", {}).items()}
                res = self.remote_sandbox({"command": b["command"], "files": files, "limits": b.get("limits", {}),
                                           "agent": node}, timeout=float(b.get("timeout", 300)))
                return 200, res.to_dict(), node
            if path == "/web/approval/request":
                need("client")
                return 200, {"request_id": self.request_approval(str(b["kind"]), str(b["action"]),
                                                                 b.get("payload"))}, node
            return 404, {"error": "unknown route"}, node
        except PermissionError as exc:
            self.audit.append("web.hub", "request.forbidden", {"node": node, "path": path, "why": str(exc)})
            return 403, {"error": str(exc)}, node
        except (KeyError, ValueError, IntegrityError, TimeoutError, RuntimeError) as exc:
            return 400, {"error": f"{type(exc).__name__}: {exc}"}, node


def make_server(hub: WebHub, host: str = "127.0.0.1", port: int = 8443, certfile: str | None = None,
                keyfile: str | None = None) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "AIPS-web"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s " + fmt, self.client_address[0], *args)

        def _do(self, method: str) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self.send_error(413)
                return
            body = self.rfile.read(n) if n else b""
            path = self.path.split("?", 1)[0]
            status, payload, node = hub.handle(method, path, body, dict(self.headers.items()), self.client_address[0])
            data = json.dumps(payload, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            if node and hub.domain.roles(node) is not None and node in hub.domain.members:
                nonce = self.headers.get("X-AIPS-Nonce", "")
                for k, v in hub.domain.sign_response(node, nonce, status, data).items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            self._do("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._do("POST")

    srv = ThreadingHTTPServer((host, port), Handler)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def serve_background(hub: WebHub, host: str = "127.0.0.1", port: int = 0, **tls: Any) -> tuple[ThreadingHTTPServer, str]:
    srv = make_server(hub, host, port, **tls)
    threading.Thread(target=srv.serve_forever, daemon=True, name="aips-web-hub").start()
    scheme = "https" if tls.get("certfile") else "http"
    return srv, f"{scheme}://{host}:{srv.server_address[1]}"
