"""Discover a Google Cloud project and turn it into an AIPS inventory.

Assets created:

* every Compute Engine VM                 -> ``host``     (id = instance name)
* every managed instance group (MIG)       -> ``service``  (id = MIG name; replicas = target size)
* every VPC network with firewall rules    -> ``network``  (id = ``net-<network>``; config = its firewall rules)

Internet exposure is computed from firewall rules: an INGRESS ``allow`` rule whose source ranges include
``0.0.0.0/0`` exposes its ports to every VM it targets (all VMs if it has no target tags). The ports exposed at
discovery time become each VM's *allowed* ports, so any port opened later is reported as unexpected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...telemetry.inventory import Asset, Inventory, SoftwareComponent
from .client import IAM, GcpClient, GcpError

WORLD = {"0.0.0.0/0", "::/0"}


@dataclass
class GcpInstance:
    name: str
    zone: str
    id: str
    status: str
    tags: list[str]
    tag_fingerprint: str
    network: str
    external_ip: str | None
    mig: str | None = None
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class GcpMig:
    name: str
    zone: str
    target_size: int
    instances: list[str] = field(default_factory=list)


@dataclass
class GcpTopology:
    project: str
    instances: dict[str, GcpInstance] = field(default_factory=dict)
    migs: dict[str, GcpMig] = field(default_factory=dict)
    firewalls: list[dict[str, Any]] = field(default_factory=list)
    service_accounts: list[dict[str, Any]] = field(default_factory=list)
    compute_unavailable: str = ""          # set when the Compute Engine API is off (e.g. no billing)

    def instance_by_id(self, instance_id: str) -> GcpInstance | None:
        return next((i for i in self.instances.values() if i.id == str(instance_id)), None)


def _last(url: str) -> str:
    return url.rsplit("/", 1)[-1] if url else ""


def expand_ports(spec: list[str] | None) -> list[int]:
    """'80', '8000-8002' -> [80, 8000, 8001, 8002]; very large ranges are represented by their first port."""
    out: list[int] = []
    for p in spec or []:
        if "-" in p:
            a, b = (int(x) for x in p.split("-", 1))
            out.extend(range(a, b + 1) if b - a <= 64 else [a])
        elif p.isdigit():
            out.append(int(p))
    return out


def firewall_config(rule: dict[str, Any]) -> dict[str, Any]:
    """The security-relevant fields of a firewall rule, normalised for drift comparison."""
    return {
        "direction": rule.get("direction", "INGRESS"),
        "priority": rule.get("priority", 1000),
        "disabled": bool(rule.get("disabled", False)),
        "sourceRanges": sorted(rule.get("sourceRanges", [])),
        "targetTags": sorted(rule.get("targetTags", [])),
        "allowed": sorted([f"{a.get('IPProtocol')}:{','.join(a.get('ports', ['all']))}" for a in rule.get("allowed", [])]),
        "denied": sorted([f"{a.get('IPProtocol')}:{','.join(a.get('ports', ['all']))}" for a in rule.get("denied", [])]),
    }


def _covers(entries: list[dict[str, Any]], port: int) -> bool:
    for a in entries:
        if a.get("IPProtocol") not in ("tcp", "all"):
            continue
        if not a.get("ports") or port == 0:
            return True
        for p in a["ports"]:
            lo, _, hi = p.partition("-")
            if int(lo) <= port <= int(hi or lo):
                return True
    return False


def exposed_ports(inst: GcpInstance, firewalls: list[dict[str, Any]]) -> list[int]:
    """TCP ports reachable from the internet, using Google Cloud's rule evaluation: among the enabled INGRESS
    rules that apply to the VM and to internet sources, the lowest priority number wins; on a tie DENY wins.
    Port 0 stands for "all ports"."""
    applicable = []
    for r in firewalls:
        if r.get("disabled") or r.get("direction", "INGRESS") != "INGRESS" or _last(r.get("network", "")) != inst.network:
            continue
        if not WORLD & set(r.get("sourceRanges", [])):
            continue
        tags = r.get("targetTags")
        if tags and not set(tags) & set(inst.tags):
            continue
        applicable.append(r)
    candidates: set[int] = set()
    for r in applicable:
        for a in r.get("allowed", []):
            if a.get("IPProtocol") in ("tcp", "all"):
                candidates.update(expand_ports(a.get("ports")) if a.get("ports") else [0])
    exposed = []
    for port in sorted(candidates):
        verdict = None                               # (priority, is_allow) of the winning rule
        for r in applicable:
            for kind, entries in (("deny", r.get("denied", [])), ("allow", r.get("allowed", []))):
                if _covers(entries, port):
                    cand = (int(r.get("priority", 1000)), kind == "allow")
                    if verdict is None or cand < verdict:   # lower priority wins; False (deny) < True on ties
                        verdict = cand
        if verdict is not None and verdict[1]:
            exposed.append(port)
    return exposed


def managed_by_aips(rule_name: str) -> bool:
    return rule_name.startswith("aips-")


class GcpDiscovery:
    def __init__(self, client: GcpClient):
        self.c = client

    def topology(self) -> GcpTopology:
        c = self.c
        topo = GcpTopology(c.project)
        try:
            self._compute(topo)
        except GcpError as exc:
            # e.g. a project without billing, where the Compute Engine API cannot be enabled: identity
            # protection (IAM + audit logs) still works, so carry on without VMs / MIGs / firewalls
            if exc.status not in (403, 404):
                raise
            topo.compute_unavailable = str(exc)
        try:
            topo.service_accounts = list(c.pages(f"{IAM}/projects/{c.project}/serviceAccounts", "accounts"))
        except Exception:  # noqa: BLE001 - IAM listing is optional (permission may be missing)
            topo.service_accounts = []
        return topo

    def _compute(self, topo: GcpTopology) -> None:
        c = self.c
        for scope, block in c.pages(f"{c.compute}/aggregated/instances", "items"):
            for i in block.get("instances", []):
                nic = (i.get("networkInterfaces") or [{}])[0]
                nat = next((ac.get("natIP") for ac in nic.get("accessConfigs", []) if ac.get("natIP")), None)
                topo.instances[i["name"]] = GcpInstance(
                    i["name"], _last(i.get("zone", scope)), str(i.get("id", "")), i.get("status", "UNKNOWN"),
                    list(i.get("tags", {}).get("items", [])), i.get("tags", {}).get("fingerprint", ""),
                    _last(nic.get("network", "")), nat, None, dict(i.get("labels", {})))
        for scope, block in c.pages(f"{c.compute}/aggregated/instanceGroupManagers", "items"):
            for m in block.get("instanceGroupManagers", []):
                zone = _last(m.get("zone", ""))
                if not zone:                       # regional MIGs: listed, but actions target zonal MIGs only
                    continue
                mig = GcpMig(m["name"], zone, int(m.get("targetSize", 0)))
                url = f"{c.compute}/zones/{zone}/instanceGroupManagers/{m['name']}/listManagedInstances"
                for mi in c.post(url).get("managedInstances", []):
                    name = _last(mi.get("instance", ""))
                    mig.instances.append(name)
                    if name in topo.instances:
                        topo.instances[name].mig = m["name"]
                topo.migs[m["name"]] = mig
        topo.firewalls = list(c.pages(f"{c.compute}/global/firewalls", "items"))

    @staticmethod
    def inventory(topo: GcpTopology, criticality: dict[str, int] | None = None) -> Inventory:
        crit = criticality or {}
        assets: list[Asset] = []
        networks = sorted({_last(r.get("network", "")) for r in topo.firewalls})
        for name, i in sorted(topo.instances.items()):
            assets.append(Asset(
                name, "host", crit.get(name, 3), depends_on=[], software=[
                    SoftwareComponent(k[len("aips-sw-"):], v) for k, v in i.labels.items() if k.startswith("aips-sw-")],
                allowed_ports=exposed_ports(i, topo.firewalls),
                attributes={"gcp": "instance", "zone": i.zone, "mig": i.mig, "network": i.network,
                            "internet_facing": i.external_ip is not None, "ntp": True}))
        for name, m in sorted(topo.migs.items()):
            assets.append(Asset(name, "service", crit.get(name, 4), depends_on=[], attributes={
                "gcp": "mig", "zone": m.zone, "replicas": m.target_size, "autoscaling": False,
                "members": m.instances}))
        for net in networks:
            assets.append(Asset(f"net-{net}", "network", crit.get(f"net-{net}", 4), attributes={
                "gcp": "network", "network": net, "transit_providers": ["google"]}))
        return Inventory(assets)

    @staticmethod
    def to_toml(inv: Inventory) -> str:
        """Render an inventory as TOML (for review / committing to configuration)."""
        def val(v: Any) -> str:
            if isinstance(v, bool):
                return "true" if v else "false"
            if isinstance(v, (int, float)):
                return str(v)
            if v is None:
                return '""'
            if isinstance(v, list):
                return "[" + ", ".join(val(x) for x in v) + "]"
            return '"' + str(v).replace('"', '\\"') + '"'
        out = ["# Generated by `aips gcp discover`. Review criticality and dependencies before use.", ""]
        for a in inv:
            out += ["[[assets]]", f"id = {val(a.id)}", f"kind = {val(a.kind)}", f"criticality = {a.criticality}",
                    f"depends_on = {val(a.depends_on)}", f"allowed_ports = {val(a.allowed_ports)}"]
            attrs = ", ".join(f"{k} = {val(v)}" for k, v in a.attributes.items())
            out.append(f"attributes = {{ {attrs} }}")
            if a.software:
                out.append("software = [" + ", ".join(f'{{ name = {val(s.name)}, version = {val(s.version)} }}'
                                                      for s in a.software) + "]")
            out.append("")
        return "\n".join(out)
