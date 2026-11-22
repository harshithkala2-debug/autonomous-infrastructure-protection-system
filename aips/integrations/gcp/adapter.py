"""Google Cloud action adapter: how AIPS changes a Google Cloud project.

=========================  ===============================================================  ==========================
AIPS action                 Google Cloud call                                                Rollback
=========================  ===============================================================  ==========================
service.restart (VM)        ``instances.reset``                                              -
service.restart (MIG)       ``instanceGroupManagers.applyUpdatesToInstances`` (RESTART)       -
service.scale_out (MIG)     ``instanceGroupManagers.resize`` to target + n                    resize back
network.block_port          new firewall rule ``aips-block-<port>`` DENY tcp:<port>, prio 100  delete the rule
host.isolate (VM)           add network tag ``aips-quarantine`` (+ deny-all rules for it)     remove the tag
config.restore_baseline     PATCH drifted firewall rules back to baseline; DISABLE new         PATCH back / re-enable
                            (unapproved) rules - never delete
freeze_identity (hook)      ``serviceAccounts.disable`` (service accounts only)              ``serviceAccounts.enable``
=========================  ===============================================================  ==========================

Every call waits for its long-running operation to finish, so verification starts from the real result.
Anything not listed returns a clear "not supported" failure rather than guessing.
"""

from __future__ import annotations

import re
import time
from typing import Any

from ...core.models import ActionRequest, ActionResult
from ...repair.baseline import DesiredStateStore
from ...repair.executor import InfrastructureAdapter
from .client import IAM, GcpClient, GcpError
from .discovery import GcpDiscovery, GcpTopology, firewall_config, managed_by_aips

QUARANTINE_TAG = "aips-quarantine"
_NAME = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")


class GcpAdapter(InfrastructureAdapter):
    name = "gcp"

    def __init__(self, client: GcpClient, topology: GcpTopology | None = None,
                 baselines: DesiredStateStore | None = None, wait: bool = True):
        self.c = client
        self._topology = topology
        self.baselines = baselines
        self.wait_ops = wait
        self.topology_ttl_s = 60.0
        self._topo_at = time.monotonic() if topology is not None else 0.0

    # ------------------------------------------------------------------ helpers
    @property
    def topology(self) -> GcpTopology:
        if self._topology is None or time.monotonic() - self._topo_at > self.topology_ttl_s:
            self.refresh()
        return self._topology

    def refresh(self) -> None:
        self._topology = GcpDiscovery(self.c).topology()
        self._topo_at = time.monotonic()

    def _op(self, op: Any) -> Any:
        return self.c.wait(op) if self.wait_ops else op

    def _ok(self, req: ActionRequest, detail: str, rollback: dict | None = None) -> ActionResult:
        return ActionResult(req.id, req.kind, req.target, True, detail, rollback=rollback)

    def _fail(self, req: ActionRequest, detail: str) -> ActionResult:
        return ActionResult(req.id, req.kind, req.target, False, detail)

    # ------------------------------------------------------------------ actions
    def execute(self, req: ActionRequest) -> ActionResult:
        if not _NAME.match(req.target) and not req.target.startswith("net-"):
            return self._fail(req, f"refused: '{req.target}' is not a valid Google Cloud resource name")
        try:
            handler = {
                "service.restart": self._restart, "service.scale_out": self._scale_out,
                "network.block_port": self._block_port, "host.isolate": self._isolate,
                "config.restore_baseline": self._restore_firewall,
            }.get(req.kind)
            if handler is None:
                return self._fail(req, f"{req.kind} is not supported by the Google Cloud adapter")
            return handler(req)
        except GcpError as exc:
            return self._fail(req, str(exc))

    def _restart(self, req: ActionRequest) -> ActionResult:
        t = self.topology
        c = self.c
        if req.target in t.migs:
            m = t.migs[req.target]
            self._op(c.post(f"{c.compute}/zones/{m.zone}/instanceGroupManagers/{m.name}/applyUpdatesToInstances",
                            {"allInstances": True, "minimalAction": "RESTART",
                             "mostDisruptiveAllowedAction": "RESTART"}))
            return self._ok(req, f"restarted all {len(m.instances)} instance(s) of MIG {m.name}")
        if req.target in t.instances:
            i = t.instances[req.target]
            self._op(c.post(f"{c.compute}/zones/{i.zone}/instances/{i.name}/reset"))
            return self._ok(req, f"reset VM {i.name}")
        return self._fail(req, f"unknown VM or MIG {req.target}")

    def _scale_out(self, req: ActionRequest) -> ActionResult:
        m = self.topology.migs.get(req.target)
        if m is None:
            return self._fail(req, f"{req.target} is not a managed instance group")
        c = self.c
        cur = int(c.get(f"{c.compute}/zones/{m.zone}/instanceGroupManagers/{m.name}").get("targetSize", m.target_size))
        new = cur + max(1, min(int(req.params.get("replicas", 1)), 10))
        self._op(c.post(f"{c.compute}/zones/{m.zone}/instanceGroupManagers/{m.name}/resize", size=new))
        m.target_size = new
        return self._ok(req, f"MIG {m.name} resized {cur} -> {new}", {"mig": m.name, "zone": m.zone, "size": cur})

    def _block_port(self, req: ActionRequest) -> ActionResult:
        port = int(req.params.get("port", 0))
        if not 0 < port < 65536:
            return self._fail(req, f"invalid port {port}")
        i = self.topology.instances.get(req.target)
        if i is None:
            return self._fail(req, f"unknown VM {req.target}")
        c = self.c
        name = f"aips-block-{port}-{i.name}"[:63].rstrip("-")
        body = {"name": name, "network": f"projects/{c.project}/global/networks/{i.network}",
                "direction": "INGRESS", "priority": 100, "sourceRanges": ["0.0.0.0/0"],
                "denied": [{"IPProtocol": "tcp", "ports": [str(port)]}],
                "description": f"AIPS: block unexpected port {port} on {i.name} (incident {req.incident_id})"}
        if i.tags:
            body["targetTags"] = list(i.tags)
        self._op(c.post(f"{c.compute}/global/firewalls", body))
        return self._ok(req, f"firewall rule {name} denies tcp:{port}", {"firewall": name})

    def _isolate(self, req: ActionRequest) -> ActionResult:
        i = self.topology.instances.get(req.target)
        if i is None:
            return self._fail(req, f"unknown VM {req.target}")
        c = self.c
        existing = {r["name"] for r in self.topology.firewalls}
        for direction, rng in (("INGRESS", "sourceRanges"), ("EGRESS", "destinationRanges")):
            rule = f"aips-quarantine-{direction.lower()}-{i.network}"[:63]
            if rule not in existing:
                self._op(c.post(f"{c.compute}/global/firewalls", {
                    "name": rule, "network": f"projects/{c.project}/global/networks/{i.network}",
                    "direction": direction, "priority": 0, rng: ["0.0.0.0/0"], "targetTags": [QUARANTINE_TAG],
                    "denied": [{"IPProtocol": "all"}], "description": "AIPS quarantine"}))
        cur = c.get(f"{c.compute}/zones/{i.zone}/instances/{i.name}").get("tags", {})
        items = sorted(set(cur.get("items", [])) | {QUARANTINE_TAG})
        self._op(c.post(f"{c.compute}/zones/{i.zone}/instances/{i.name}/setTags",
                        {"items": items, "fingerprint": cur.get("fingerprint", i.tag_fingerprint)}))
        return self._ok(req, f"VM {i.name} quarantined (tag {QUARANTINE_TAG})", {"untag": i.name, "zone": i.zone})

    def _restore_firewall(self, req: ActionRequest) -> ActionResult:
        if not req.target.startswith("net-") or self.baselines is None:
            return self._fail(req, "config restore is supported for firewall configuration (net-*) only")
        b = self.baselines.get(req.target)
        if b is None:
            return self._fail(req, f"no baseline recorded for {req.target}")
        c = self.c
        live = {r["name"]: r for r in c.pages(f"{c.compute}/global/firewalls", "items")}
        restored, previous = [], {}
        for name, want in b.config.items():
            have = live.get(name)
            if have is None:
                continue                              # rule deleted since baseline: needs a human
            patch = {"sourceRanges": want["sourceRanges"], "disabled": want["disabled"], "priority": want["priority"]}
            cur = firewall_config(have)
            if any(cur[k] != want[k] for k in ("sourceRanges", "disabled", "priority", "allowed", "targetTags")):
                previous[name] = {"sourceRanges": have.get("sourceRanges", []), "disabled": have.get("disabled", False),
                                  "priority": have.get("priority", 1000)}
                if cur["allowed"] != want["allowed"]:
                    patch["allowed"] = [_parse_rule(x) for x in want["allowed"]]
                if cur["targetTags"] != want["targetTags"]:
                    patch["targetTags"] = want["targetTags"]
                self._op(c.patch(f"{c.compute}/global/firewalls/{name}", patch))
                restored.append(name)
        net = req.target[len("net-"):]
        added = [n for n, r in live.items() if n not in b.config and not managed_by_aips(n) and not r.get("disabled")
                 and r.get("network", "").rsplit("/", 1)[-1] == net]
        for name in added:
            # a rule that was not part of the known-good state is DISABLED (kept for forensics, reversible),
            # never deleted
            previous[name] = {"disabled": False}
            self._op(c.patch(f"{c.compute}/global/firewalls/{name}", {"disabled": True}))
        missing = [n for n in b.config if n not in live]
        detail = (f"restored {len(restored)} firewall rule(s), disabled {len(added)} unapproved rule(s)"
                  + (f": {', '.join(added)}" if added else "")
                  + (f"; {len(missing)} baseline rule(s) deleted, need a human: {', '.join(missing)}" if missing else ""))
        return self._ok(req, detail, {"firewalls": previous})

    # ------------------------------------------------------------------ identity hook
    def freeze_identity(self, identity: str, frozen: bool) -> tuple[bool, str]:
        """Enforce an AIPS freeze in Google Cloud. Only service accounts can be disabled through IAM."""
        if not identity.endswith(".gserviceaccount.com"):
            return False, "only service accounts can be disabled in Google Cloud; human users need the Admin console"
        verb = "disable" if frozen else "enable"
        try:
            self.c.post(f"{IAM}/projects/-/serviceAccounts/{identity}:{verb}")
        except GcpError as exc:
            return False, str(exc)
        return True, f"service account {identity} {verb}d in Google Cloud IAM"

    # ------------------------------------------------------------------ rollback / health
    def rollback(self, result: ActionResult) -> ActionResult:
        rb = result.rollback or {}
        c = self.c
        try:
            if "firewall" in rb:
                self._op(c.delete(f"{c.compute}/global/firewalls/{rb['firewall']}"))
            elif "mig" in rb:
                self._op(c.post(f"{c.compute}/zones/{rb['zone']}/instanceGroupManagers/{rb['mig']}/resize",
                                size=rb["size"]))
            elif "untag" in rb:
                cur = c.get(f"{c.compute}/zones/{rb['zone']}/instances/{rb['untag']}").get("tags", {})
                self._op(c.post(f"{c.compute}/zones/{rb['zone']}/instances/{rb['untag']}/setTags",
                                {"items": [t for t in cur.get("items", []) if t != QUARANTINE_TAG],
                                 "fingerprint": cur.get("fingerprint", "")}))
            elif "firewalls" in rb:
                for name, prev in rb["firewalls"].items():
                    self._op(c.patch(f"{c.compute}/global/firewalls/{name}", prev))
            else:
                return ActionResult(result.action_id, result.kind + ".rollback", result.target, False, "no rollback data")
        except GcpError as exc:
            return ActionResult(result.action_id, result.kind + ".rollback", result.target, False, str(exc))
        return ActionResult(result.action_id, result.kind + ".rollback", result.target, True, "rolled back")

    def health(self, asset_id: str) -> bool | None:
        t = self.topology
        if asset_id in t.instances:
            i = t.instances[asset_id]
            try:
                return self.c.get(f"{self.c.compute}/zones/{i.zone}/instances/{i.name}").get("status") == "RUNNING"
            except GcpError:
                return None
        return None


def _parse_rule(s: str) -> dict[str, Any]:
    proto, _, ports = s.partition(":")
    out: dict[str, Any] = {"IPProtocol": proto}
    if ports and ports != "all":
        out["ports"] = ports.split(",")
    return out
