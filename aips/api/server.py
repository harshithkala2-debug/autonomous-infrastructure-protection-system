"""Control-plane HTTP API (standard library only).

Authentication: ``Authorization: Bearer <token>`` (constant-time compare).
``GET /health`` is unauthenticated for load-balancer probes; everything else
requires the token. Human identities for approvals / appeals are passed in
the request body and recorded in the audit ledger.

Endpoints::

    GET  /health                          liveness
    GET  /status                          system overview
    GET  /metrics                         Prometheus text format
    GET  /incidents[?status=open]         incidents
    GET  /incidents/{id}                  one incident with full timeline
    POST /incidents/{id}/close            {"by", "resolution", "false_positive"}
    GET  /approvals                       pending approvals
    POST /approvals/{id}/approve          {"approver", "note"}
    POST /approvals/{id}/reject           {"approver", "note"}
    GET  /valves                          valve positions
    POST /killswitch                      {"engaged": true, "by", "reason"}
    POST /access-events                   {"identity_id","action","resource","source_ip","success","session_id"}
    POST /findings                        external finding injection (same schema as ExternalAlertDetector)
    POST /appeals                         {"identity_id", "submitted_by", "reason"}
    POST /appeals/{id}/review             {"reviewer","grant","note","allow_action","allow_resource"}
    POST /baselines/{asset}               {"approved_by"} - capture current config as known-good
    GET  /mesh                            layer capabilities, call statistics, recent inter-layer calls
    POST /mesh/call                       {"target","capability","payload"} - read-only capabilities only
    GET  /experience[?signal=&asset=]     history summary, per-strategy track record, similar episodes
    POST /agents/check                    {"agent","tool","args","session","cwd"} - judge an AI agent's tool call
    POST /agents/result                   {"call_id","success","output"} - report what the call returned
    GET  /agents[?agent=]                 agent guard status and recent tool calls
    POST /agents/{agent}/release          {"by","reason"} - a human unfreezes an agent (URL-encode the id)
    GET  /audit?limit=100                 recent audit records
    GET  /audit/verify                    verify the hash chain
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

from ..agents.guard import ToolCall
from ..core.models import Category, Evidence, Finding, IncidentStatus, Severity, to_jsonable
from ..identity.guard import AccessEvent
from ..orchestrator import AIPS

log = logging.getLogger("aips.api")
MAX_BODY = 1 << 20


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def make_handler(aips: AIPS, token: str, lock: threading.RLock) -> type[BaseHTTPRequestHandler]:
    routes: list[tuple[str, str, Callable[..., Any]]] = []

    def route(method: str, pattern: str):
        def deco(fn):
            routes.append((method, pattern, fn))
            return fn
        return deco

    def match(pattern: str, path: str) -> dict[str, str] | None:
        pp, sp = pattern.strip("/").split("/"), path.strip("/").split("/")
        if len(pp) != len(sp):
            return None
        out = {}
        for a, b in zip(pp, sp):
            if a.startswith("{"):
                out[a[1:-1]] = unquote(b)
            elif a != b:
                return None
        return out

    def need(body: dict, *keys: str) -> None:
        missing = [k for k in keys if not body.get(k)]
        if missing:
            raise ApiError(400, f"missing field(s): {', '.join(missing)}")

    @route("GET", "/status")
    def status(q, b):
        return aips.status()

    @route("GET", "/incidents")
    def incidents(q, b):
        st = q.get("status", [None])[0]
        items = [i for i in aips.engine.incidents.values() if st is None or i.status.value == st]
        return [{"id": i.id, "asset": i.asset_id, "category": i.category.value, "signal": i.signal,
                 "severity": i.severity.name, "status": i.status.value, "level": i.level.name,
                 "playbook": i.playbook, "opened_at": i.opened_at, "resolved_at": i.resolved_at,
                 "actions": len(i.actions), "root_cause_asset": i.root_cause_asset} for i in items]

    @route("GET", "/incidents/{id}")
    def incident(q, b, id):
        if id not in aips.engine.incidents:
            raise ApiError(404, "incident not found")
        return aips.incident_view(id)

    @route("POST", "/incidents/{id}/close")
    def close(q, b, id):
        need(b, "by", "resolution")
        if id not in aips.engine.incidents:
            raise ApiError(404, "incident not found")
        inc = aips.engine.close_human_incident(id, b["by"], b["resolution"], bool(b.get("false_positive")))
        return {"id": inc.id, "status": inc.status.value}

    @route("GET", "/approvals")
    def approvals(q, b):
        return [{"id": a.id, "kind": a.request.kind, "target": a.request.target, "params": a.request.params,
                 "risk": a.request.risk.name, "reason": a.reason, "incident": a.request.incident_id,
                 "approvals_required": a.approvals_required, "approvers": a.approvers, "created_at": a.created_at}
                for a in aips.approvals.pending()]

    @route("POST", "/approvals/{id}/approve")
    def approve(q, b, id):
        need(b, "approver")
        return aips.approve(id, b["approver"], b.get("note", ""))

    @route("POST", "/approvals/{id}/reject")
    def reject(q, b, id):
        need(b, "approver")
        return aips.reject(id, b["approver"], b.get("note", ""))

    @route("GET", "/valves")
    def valves(q, b):
        return aips.traffic.snapshot()

    @route("POST", "/killswitch")
    def killswitch(q, b):
        need(b, "by")
        aips.set_kill_switch(bool(b.get("engaged", True)), b["by"], b.get("reason", ""))
        return {"kill_switch": aips.policy.kill_switch}

    @route("POST", "/access-events")
    def access(q, b):
        need(b, "identity_id", "action", "resource")
        dec = aips.ingest_access(AccessEvent(b["identity_id"], b["action"], b["resource"],
                                             float(b.get("ts") or aips.clock.now()), b.get("source_ip"),
                                             bool(b.get("success", True)), b.get("session_id")))
        return {"allowed": dec.allowed, "risk": dec.risk, "reasons": dec.reasons,
                "finding": dec.finding.id if dec.finding else None}

    @route("POST", "/findings")
    def findings(q, b):
        need(b, "asset", "title")
        f = Finding(detector=f"external:{b.get('source', 'api')}", category=Category(b.get("category", "security")),
                    severity=Severity.parse(b.get("severity", "MEDIUM")),
                    confidence=float(b.get("confidence", 0.7)), asset_id=b["asset"], title=b["title"],
                    description=b.get("description", ""), created_at=aips.clock.now(),
                    signal=b.get("signal", "external_alert"),
                    evidence=[Evidence("alert", b.get("source", "api"), dict(b), aips.clock.now())])
        aips.ingest_findings([f])
        return {"accepted": f.id}

    @route("POST", "/appeals")
    def appeal(q, b):
        need(b, "identity_id", "submitted_by", "reason")
        try:
            return aips.submit_appeal(b["identity_id"], b["submitted_by"], b["reason"])
        except ValueError as exc:
            raise ApiError(409, str(exc)) from exc

    @route("POST", "/appeals/{id}/review")
    def review(q, b, id):
        need(b, "reviewer")
        if "grant" not in b:
            raise ApiError(400, "missing field: grant")
        return aips.review_appeal(id, b["reviewer"], bool(b["grant"]), b.get("note", ""), b.get("allow_action"),
                                  b.get("allow_resource", "*"))

    @route("POST", "/baselines/{asset}")
    def baseline(q, b, asset):
        need(b, "approved_by")
        return aips.capture_baseline(asset, b["approved_by"])

    @route("GET", "/audit")
    def audit(q, b):
        limit = min(1000, int(q.get("limit", ["100"])[0]))
        return [r.__dict__ for r in aips.audit.records(q.get("prefix", [None])[0], limit)]

    @route("GET", "/mesh")
    def mesh(q, b):
        return {"capabilities": aips.mesh.capabilities(), "stats": aips.mesh.snapshot(),
                "recent": aips.mesh.recent(int(q.get("limit", ["50"])[0]))}

    @route("POST", "/mesh/call")
    def mesh_call(q, b):
        need(b, "target", "capability")
        caps = {(c["layer"], c["capability"]): c for c in aips.mesh.capabilities()}
        cap = caps.get((b["target"], b["capability"]))
        if cap is None:
            raise ApiError(404, "unknown capability")
        if cap["mutating"] or b["capability"] == "escalate":
            raise ApiError(403, "only read-only capabilities can be called over the API")
        res = aips.mesh.call("api", b["target"], b["capability"], b.get("payload") or {})
        return {"ok": res.ok, "value": res.value, "error": res.error}

    @route("GET", "/experience")
    def experience(q, b):
        sig = q.get("signal", [None])[0]
        out = {"summary": aips.experience.summary()}
        if sig:
            out["strategies"] = aips.experience.strategy_stats(sig, q.get("asset", [None])[0])
            out["similar"] = aips.experience.similar(sig, q.get("asset", [None])[0], 10)
        return out

    @route("POST", "/agents/check")
    def agent_check(q, b):
        need(b, "agent", "tool")
        if not isinstance(b.get("args", {}), dict):
            raise ApiError(400, "args must be an object")
        d = aips.check_agent_call(ToolCall(str(b["agent"]), str(b["tool"]), dict(b.get("args") or {}),
                                           b.get("session"), b.get("cwd"), call_id=b.get("call_id")))
        return {"call_id": d.call_id, "verdict": d.verdict.value, "allowed": d.allowed, "risk": d.risk,
                "reasons": d.reasons, "checkpoints": d.checkpoints, "frozen": aips.agents.is_frozen(d.agent_id)}

    @route("POST", "/agents/result")
    def agent_result(q, b):
        need(b, "call_id")
        return aips.agent_result(str(b["call_id"]), bool(b.get("success", True)), b.get("output"))

    @route("GET", "/agents")
    def agents(q, b):
        return {"status": aips.agents.snapshot(),
                "recent": aips.agents.history(q.get("agent", [None])[0], int(q.get("limit", ["50"])[0]))}

    @route("POST", "/agents/{agent}/release")
    def agent_release(q, b, agent):
        need(b, "by")
        return aips.release_agent(agent, b["by"], b.get("reason", ""))

    @route("GET", "/audit/verify")
    def audit_verify(q, b):
        ok, bad, reason = aips.audit.verify()
        return {"ok": ok, "first_bad_seq": bad, "reason": reason}

    class Handler(BaseHTTPRequestHandler):
        server_version = "aips"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # route through logging
            log.info("%s %s", self.address_string(), fmt % args)

        def _send(self, status: int, payload: Any, ctype: str = "application/json") -> None:
            body = payload.encode() if isinstance(payload, str) else json.dumps(to_jsonable(payload), default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _authorised(self) -> bool:
            h = self.headers.get("Authorization", "")
            return h.startswith("Bearer ") and hmac.compare_digest(h[7:].encode(), token.encode())

        def _dispatch(self, method: str) -> None:
            url = urlparse(self.path)
            if method == "GET" and url.path == "/health":
                return self._send(200, {"ok": True})
            if not self._authorised():
                return self._send(401, {"error": "unauthorised"})
            if method == "GET" and url.path == "/metrics":
                with lock:
                    return self._send(200, aips.metrics_text(), "text/plain; version=0.0.4")
            body: dict[str, Any] = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    return self._send(413, {"error": "body too large"})
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                    if not isinstance(body, dict):
                        raise ValueError
                except ValueError:
                    return self._send(400, {"error": "body must be a JSON object"})
            for m, pattern, fn in routes:
                if m != method:
                    continue
                params = match(pattern, url.path)
                if params is None:
                    continue
                try:
                    with lock:
                        return self._send(200, fn(parse_qs(url.query), body, **params))
                except ApiError as exc:
                    return self._send(exc.status, {"error": str(exc)})
                except (KeyError, ValueError) as exc:
                    return self._send(400, {"error": str(exc)})
            return self._send(404, {"error": "not found"})

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

    return Handler


def serve(aips: AIPS, host: str, port: int, token: str, lock: threading.RLock | None = None) -> ThreadingHTTPServer:
    if not token or len(token) < 16:
        raise ValueError("API token must be at least 16 characters")
    lock = lock or threading.RLock()
    srv = ThreadingHTTPServer((host, port), make_handler(aips, token, lock))
    t = threading.Thread(target=srv.serve_forever, name="aips-api", daemon=True)
    t.start()
    log.info("API listening on http://%s:%d", host, srv.server_address[1])
    return srv


__all__ = ["serve", "make_handler", "IncidentStatus"]
