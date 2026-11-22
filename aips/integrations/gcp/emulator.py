"""In-process emulator of the Google Cloud REST APIs that AIPS uses.

It is a *transport* for ``GcpClient``: requests are answered from in-memory project state, and actions change
that state, so the whole integration (discovery -> telemetry -> decisions -> actions -> verification) can be
exercised end to end without an account. Response shapes follow the public API documentation for:

* Compute Engine v1: aggregated instances / instance group managers, instances get/reset/setTags,
  instanceGroupManagers get/resize/applyUpdatesToInstances/listManagedInstances, firewalls CRUD, operations;
* Cloud Monitoring v3: projects.timeSeries.list;
* Cloud Logging v2: entries.list;
* IAM v1: serviceAccounts list / disable / enable;
* Security Command Center v2: findings list.

Long-running operations are returned as RUNNING and report DONE on the next poll, so operation waiting is tested.
"""

from __future__ import annotations

import copy
import itertools
import json
import re
import urllib.parse
from typing import Any

from .sources import rfc3339


class FakeGcp:
    def __init__(self, project: str = "demo-project", zone: str = "us-central1-a"):
        self.project, self.zone = project, zone
        self.instances: dict[str, dict[str, Any]] = {}
        self.migs: dict[str, dict[str, Any]] = {}
        self.firewalls: dict[str, dict[str, Any]] = {}
        self.service_accounts: dict[str, dict[str, Any]] = {}
        self.cpu: dict[str, float] = {}                 # instance name -> utilisation 0..1
        self.uptime: dict[str, float] = {}              # check id -> fraction passing
        self.log_entries: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str, Any]] = []
        self.fail: dict[str, int] = {}                  # url substring -> HTTP status to return
        self.keys: dict[str, dict[str, Any]] = {}
        self.policy: dict[str, Any] = {"version": 1, "etag": "etag-0", "bindings": [
            {"role": "roles/owner", "members": ["user:owner@example.com"]}]}
        self._ids = itertools.count(1000)
        self._ops: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ building the project
    def add_instance(self, name: str, tags: list[str] | None = None, external: bool = True,
                     status: str = "RUNNING", network: str = "default", cpu: float = 0.3) -> dict[str, Any]:
        inst = {"name": name, "id": str(next(self._ids)), "status": status,
                "zone": f"projects/{self.project}/zones/{self.zone}",
                "tags": {"items": list(tags or []), "fingerprint": "fp-0"},
                "networkInterfaces": [{"network": f"projects/{self.project}/global/networks/{network}",
                                       "accessConfigs": [{"natIP": "34.1.2.3"}] if external else []}],
                "labels": {}}
        self.instances[name] = inst
        self.cpu[name] = cpu
        return inst

    def add_mig(self, name: str, size: int, tags: list[str] | None = None) -> None:
        members = [self.add_instance(f"{name}-{i:04d}", tags) ["name"] for i in range(size)]
        self.migs[name] = {"name": name, "zone": f"projects/{self.project}/zones/{self.zone}", "targetSize": size,
                           "members": members, "tags": list(tags or [])}

    def add_firewall(self, name: str, ports: list[str], source: str = "0.0.0.0/0", tags: list[str] | None = None,
                     priority: int = 1000, network: str = "default", deny: bool = False) -> None:
        rule = {"name": name, "network": f"projects/{self.project}/global/networks/{network}",
                "direction": "INGRESS", "priority": priority, "sourceRanges": [source], "disabled": False,
                ("denied" if deny else "allowed"): [{"IPProtocol": "tcp", "ports": ports}]}
        if tags:
            rule["targetTags"] = tags
        self.firewalls[name] = rule

    def add_service_account(self, email: str) -> None:
        self.service_accounts[email] = {"email": email, "name": f"projects/{self.project}/serviceAccounts/{email}",
                                        "disabled": False}

    def audit(self, principal: str, service: str, method: str, resource: str, ip: str, ts: float,
              code: int = 0, response: dict | None = None, deltas: list[dict] | None = None) -> None:
        payload = {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": service, "methodName": method,
            "resourceName": resource, "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": ip}, "status": {"code": code} if code else {}}
        if response:
            payload["response"] = response
        if deltas:
            payload["serviceData"] = {"policyDelta": {"bindingDeltas": deltas}}
        self.log_entries.append({"insertId": f"e{next(self._ids)}", "timestamp": rfc3339(ts), "protoPayload": payload})

    # ------------------------------------------------------------------ transport
    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, Any]:
        data = json.loads(body) if body else None
        self.requests.append((method, url, data))
        for frag, status in self.fail.items():
            if frag in url:
                return status, {"error": {"code": status, "message": f"emulated failure for {frag}"}}
        u = urllib.parse.urlparse(url)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        path = u.path
        try:
            if u.netloc == "compute.googleapis.com":
                return self._compute(method, path.split(f"/projects/{self.project}/", 1)[1], q, data)
            if u.netloc == "monitoring.googleapis.com":
                return self._monitoring(q)
            if u.netloc == "logging.googleapis.com":
                out, self.log_entries = self.log_entries, []
                return 200, {"entries": out}
            if u.netloc == "iam.googleapis.com":
                return self._iam(method, path)
            if u.netloc == "cloudresourcemanager.googleapis.com":
                return self._resource_manager(path, data)
            if u.netloc == "securitycenter.googleapis.com":
                return 200, {"listFindingsResults": [{"finding": f} for f in self.findings]}
        except KeyError as exc:
            return 404, {"error": {"code": 404, "message": f"not found: {exc}"}}
        return 404, {"error": {"code": 404, "message": f"unknown endpoint {url}"}}

    def _op(self, scope: str = "zone") -> tuple[int, dict[str, Any]]:
        name = f"operation-{next(self._ids)}"
        op = {"name": name, "status": "RUNNING"}
        if scope == "zone":
            op["zone"] = f"projects/{self.project}/zones/{self.zone}"
        self._ops[name] = op
        return 200, dict(op)

    def _compute(self, method: str, path: str, q: dict[str, str], data: Any) -> tuple[int, Any]:
        parts = path.split("/")
        if path == "aggregated/instances":
            return 200, {"items": {f"zones/{self.zone}": {"instances": [copy.deepcopy(i) for i in self.instances.values()]}}}
        if path == "aggregated/instanceGroupManagers":
            return 200, {"items": {f"zones/{self.zone}": {"instanceGroupManagers": [
                {"name": m["name"], "zone": m["zone"], "targetSize": m["targetSize"]} for m in self.migs.values()]}}}
        if parts[0] in ("zones", "global") and "operations" in parts:
            op = self._ops[parts[-1]]
            op["status"] = "DONE"
            return 200, dict(op)
        if path == "global/firewalls":
            if method == "GET":
                return 200, {"items": [copy.deepcopy(r) for r in self.firewalls.values()]}
            if data["name"] in self.firewalls:
                return 409, {"error": {"code": 409, "message": "already exists"}}
            self.firewalls[data["name"]] = {"disabled": False, **data}
            return self._op("global")
        if parts[:2] == ["global", "firewalls"]:
            name = parts[2]
            if method == "GET":
                return 200, copy.deepcopy(self.firewalls[name])
            if method == "DELETE":
                del self.firewalls[name]
                return self._op("global")
            self.firewalls[name].update(data)          # PATCH
            return self._op("global")
        if parts[0] == "zones" and parts[2] == "instances":
            inst = self.instances[parts[3]]
            if len(parts) == 4:
                return 200, copy.deepcopy(inst)
            if parts[4] == "reset":
                inst["status"] = "RUNNING"
                return self._op()
            if parts[4] == "setTags":
                if data.get("fingerprint") != inst["tags"]["fingerprint"]:
                    return 412, {"error": {"code": 412, "message": "fingerprint mismatch"}}
                n = int(inst["tags"]["fingerprint"].split("-")[1]) + 1
                inst["tags"] = {"items": list(data.get("items", [])), "fingerprint": f"fp-{n}"}
                return self._op()
        if parts[0] == "zones" and parts[2] == "instanceGroupManagers":
            m = self.migs[parts[3]]
            if len(parts) == 4:
                return 200, {"name": m["name"], "zone": m["zone"], "targetSize": m["targetSize"]}
            verb = parts[4]
            if verb == "listManagedInstances":
                return 200, {"managedInstances": [
                    {"instance": f"projects/{self.project}/zones/{self.zone}/instances/{n}",
                     "instanceStatus": self.instances[n]["status"]} for n in m["members"]]}
            if verb == "resize":
                size = int(q["size"])
                while len(m["members"]) < size:
                    m["members"].append(self.add_instance(f"{m['name']}-{len(m['members']):04d}", m["tags"])["name"])
                while len(m["members"]) > size:
                    self.instances.pop(m["members"].pop(), None)
                m["targetSize"] = size
                return self._op()
            if verb == "applyUpdatesToInstances":
                for n in m["members"]:
                    self.instances[n]["status"] = "RUNNING"
                return self._op()
        raise KeyError(path)

    def _monitoring(self, q: dict[str, str]) -> tuple[int, Any]:
        mtype = re.search(r'metric\.type = "([^"]+)"', q.get("filter", ""))
        mtype = mtype.group(1) if mtype else ""
        series = []
        if mtype == "compute.googleapis.com/instance/cpu/utilization":
            for name, v in self.cpu.items():
                if name in self.instances and self.instances[name]["status"] == "RUNNING":
                    series.append({"metric": {"type": mtype}, "resource": {"type": "gce_instance", "labels": {
                        "instance_id": self.instances[name]["id"], "zone": self.zone}},
                        "points": [{"value": {"doubleValue": v}}]})
        elif mtype == "monitoring.googleapis.com/uptime_check/check_passed":
            for check, frac in self.uptime.items():
                series.append({"metric": {"type": mtype, "labels": {"check_id": check}},
                               "resource": {"type": "uptime_url"}, "points": [{"value": {"doubleValue": frac}}]})
        return 200, {"timeSeries": series}

    def _iam(self, method: str, path: str) -> tuple[int, Any]:
        if method == "GET":
            return 200, {"accounts": [dict(a) for a in self.service_accounts.values()]}
        last = path.rsplit("/", 1)[-1]
        target, _, verb = last.partition(":")
        if "/keys/" in path:
            self.keys[path.split(":")[0].split("/v1/", 1)[1]]["disabled"] = verb == "disable"
            return 200, {}
        self.service_accounts[target]["disabled"] = verb == "disable"
        return 200, {}

    def _resource_manager(self, path: str, data: Any) -> tuple[int, Any]:
        verb = path.rsplit(":", 1)[-1]
        if verb == "getIamPolicy":
            return 200, copy.deepcopy(self.policy)
        if verb == "setIamPolicy":
            new = data["policy"]
            if new.get("etag") != self.policy["etag"]:
                return 409, {"error": {"code": 409, "message": "etag mismatch (concurrent policy change)"}}
            n = int(self.policy["etag"].split("-")[1]) + 1
            self.policy = {**copy.deepcopy(new), "etag": f"etag-{n}"}
            return 200, copy.deepcopy(self.policy)
        raise KeyError(path)

    # -- helpers for tests: what an attacker would do through the real API (and what Google would log) -------
    def create_key(self, email: str) -> str:
        name = f"projects/{self.project}/serviceAccounts/{email}/keys/k{next(self._ids)}"
        self.keys[name] = {"name": name, "disabled": False}
        return name

    def grant(self, member: str, role: str) -> None:
        b = next((x for x in self.policy["bindings"] if x["role"] == role), None)
        if b is None:
            self.policy["bindings"].append({"role": role, "members": [member]})
        elif member not in b["members"]:
            b["members"].append(member)

    def members(self, role: str) -> list[str]:
        return next((list(b["members"]) for b in self.policy["bindings"] if b["role"] == role), [])
