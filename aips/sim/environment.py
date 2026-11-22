"""Simulated infrastructure.

``SimulatedInfrastructure`` is both a ``TelemetrySource`` and an
``InfrastructureAdapter``: AIPS observes it and acts on it exactly as it would
on real systems. The model is simple but causal:

* each service has demand (req/s), capacity (replicas x per-replica capacity)
  and an ingress valve; saturation = demand x ingress_position / capacity;
* saturation > 1 produces errors and latency; saturation drives CPU;
* a service whose dependency is down returns errors (cascading failure);
* internal valves slow internal streams (replication, queue consumption);
* disks fill when a leak fault is active; configs and ports can be tampered.

Randomness comes from a seeded ``random.Random`` so every run is reproducible.
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from typing import Any

from ..core.models import ActionRequest, ActionResult
from ..repair.baseline import DesiredStateStore
from ..repair.executor import InfrastructureAdapter
from ..telemetry.inventory import Asset, Certificate, Inventory, SoftwareComponent
from ..telemetry.sources import MetricSample, Observation, TelemetrySource


@dataclass
class SimAsset:
    id: str
    kind: str
    up: bool = True
    replicas: int = 2
    per_replica_rps: float = 500.0
    demand_rps: float = 500.0
    base_latency_ms: float = 80.0
    ingress: float = 1.0
    internal: float = 1.0
    disk_used_pct: float = 55.0
    memory_pct: float = 60.0
    replication_lag_s: float = 2.0
    config: dict[str, Any] = field(default_factory=dict)
    open_ports: list[int] = field(default_factory=list)
    isolated: bool = False
    restarts: int = 0

    @property
    def capacity(self) -> float:
        return max(1.0, self.replicas * self.per_replica_rps)


@dataclass
class Fault:
    kind: str
    asset: str
    start: int
    end: int | None = None
    params: dict[str, Any] = field(default_factory=dict)
    active: bool = False
    cleared: bool = False


def default_inventory(now: float) -> Inventory:
    year = 365 * 86400
    return Inventory([
        Asset("edge-lb", "network", 4, [], [], [80, 443], [Certificate("edge-wildcard", now + year)],
              {"transit_providers": ["isp-a", "isp-b"], "internet_facing": True}),
        Asset("web", "service", 4, ["api"], [SoftwareComponent("node.js", "20.11.0", "nodejs")], [443],
              [], {"autoscaling": True, "staged_rollout": True, "rate_limited": True, "replicas": 3}),
        Asset("api", "service", 4, ["db", "cache"],
              [SoftwareComponent("acme-gateway", "3.2.1", "acme"),
               SoftwareComponent("examplelib", "1.4.0", "", "PyPI")], [443, 8443],
              [Certificate("api-tls", now + year)],
              {"internet_facing": True, "autoscaling": True, "staged_rollout": True, "circuit_breaker": True,
               "replicas": 3, "cert_auto_renew": True}),
        Asset("db", "database", 5, [], [SoftwareComponent("postgresql", "15.3", "postgresql")], [5432],
              [], {"replicas": 2, "failover_tested": True}),
        Asset("cache", "service", 3, [], [SoftwareComponent("redis", "7.2.4", "redis")], [6379], [],
              {"replicas": 2, "rate_limited": True}),
        Asset("worker", "service", 3, ["db", "queue"], [], [], [], {"autoscaling": True, "staged_rollout": True,
                                                                    "circuit_breaker": True}),
        Asset("queue", "queue", 3, [], [], [5672], [], {"replicas": 2}),
        Asset("storage-01", "host", 3, [], [], [22], [], {"ntp": True}),
        Asset("files", "storage", 4, [], [], [445], [], {"replicas": 2}),
    ])


class SimulatedInfrastructure(TelemetrySource, InfrastructureAdapter):
    name = "simulator"

    def __init__(self, inventory: Inventory, seed: int = 7):
        self.inventory = inventory
        self.rng = random.Random(seed)
        self.assets: dict[str, SimAsset] = {}
        self.faults: list[Fault] = []
        self.tick_no = 0
        self.baselines: DesiredStateStore | None = None
        self.action_log: list[ActionRequest] = []
        self.clock_now = 0.0
        self.files_root = None          # set by the scenario for ransomware tests
        self._build()

    def _build(self) -> None:
        for a in self.inventory:
            sa = SimAsset(a.id, a.kind, open_ports=list(a.allowed_ports))
            if a.kind == "service":
                sa.replicas = int(a.attributes.get("replicas", 2))
                sa.demand_rps = 0.5 * sa.capacity
                sa.config = {"tls": {"enabled": True, "min_version": "1.2"}, "auth": {"required": True},
                             "log_level": "info", "pool_size": 50, "debug": False}
            elif a.kind == "database":
                sa.config = {"ssl": True, "max_connections": 500, "public_access": False, "audit_logging": True}
                sa.demand_rps = 400
                sa.per_replica_rps = 800
            elif a.kind == "host":
                sa.config = {"firewall": {"enabled": True, "default": "deny"}, "ssh": {"password_auth": False}}
            else:
                sa.config = {"acl": "private"}
            self.assets[a.id] = sa

    # ------------------------------------------------------------------ faults
    def inject(self, kind: str, asset: str, start: int, end: int | None = None, **params: Any) -> Fault:
        f = Fault(kind, asset, start, end, params)
        self.faults.append(f)
        return f

    def _apply_faults(self) -> None:
        t = self.tick_no
        for f in self.faults:
            if f.cleared:
                continue
            if f.start <= t and (f.end is None or t < f.end):
                first = not f.active
                f.active = True
                a = self.assets[f.asset]
                if f.kind in ("crash", "crash_loop") and first:
                    a.up = False
                elif f.kind == "config_tamper" and first:
                    node = a.config
                    path = f.params["path"].split(".")
                    for p in path[:-1]:
                        node = node.setdefault(p, {})
                    f.params["_previous"] = node.get(path[-1])
                    node[path[-1]] = f.params["value"]
                elif f.kind == "open_port" and first:
                    if f.params["port"] not in a.open_ports:
                        a.open_ports.append(f.params["port"])
                elif f.kind == "disk_leak":
                    a.disk_used_pct = min(100.0, a.disk_used_pct + f.params.get("rate", 1.5))
                elif f.kind == "ransomware" and first and not a.isolated:
                    self._encrypt_files(f.params.get("fraction", 0.6))
            elif f.active and f.end is not None and t >= f.end:
                f.active = False
                f.cleared = True
                if f.kind == "config_tamper":          # a transient change that undoes itself
                    node = self.assets[f.asset].config
                    path = f.params["path"].split(".")
                    for p in path[:-1]:
                        node = node.setdefault(p, {})
                    node[path[-1]] = f.params.get("_previous")

    def _encrypt_files(self, fraction: float) -> None:
        if not self.files_root:
            return
        from pathlib import Path
        files = sorted(p for p in Path(self.files_root).rglob("*") if p.is_file())
        for p in files[: max(1, int(len(files) * fraction))]:
            p.write_bytes(self.rng.randbytes(max(512, p.stat().st_size)))
            p.rename(p.with_name(p.name + ".locked"))

    def surge(self, asset: str) -> float:
        m = 1.0
        for f in self.faults:
            if f.active and f.kind == "traffic_surge" and f.asset == asset:
                m *= f.params.get("multiplier", 3.0)
        return m

    def spike(self, asset: str, metric: str) -> float | None:
        for f in self.faults:
            if f.active and f.kind == "noisy_spike" and f.asset == asset and f.params["metric"] == metric:
                return f.params["value"]
        return None

    # ------------------------------------------------------------------ dynamics
    def step(self, tick_no: int, now: float) -> None:
        self.tick_no, self.clock_now = tick_no, now
        self._apply_faults()
        for f in self.faults:
            if f.active and f.kind == "crash_loop":
                self.assets[f.asset].up = False

    def collect(self, now: float) -> Observation:
        obs = Observation(ts=now)
        g = self.rng.gauss
        for a in self.assets.values():
            m = obs.metrics.append
            if a.kind in ("service", "database", "queue"):
                if a.kind != "queue":
                    obs.service_up[a.id] = a.up and not a.isolated
                demand = a.demand_rps * self.surge(a.id) * (1 + g(0, 0.02))
                offered = demand * a.ingress
                sat = offered / a.capacity if a.up else 0.0
                dep_down = any(not self.assets[d].up or self.assets[d].isolated
                               for d in self.inventory.get(a.id).depends_on if d in self.assets)
                if not a.up or a.isolated:
                    err, lat, cpu = 1.0, 0.0, 0.0
                else:
                    err = 0.004 + max(0.0, g(0, 0.001)) + max(0.0, sat - 1.0) * 0.9
                    if dep_down:
                        err += 0.45
                    lat = a.base_latency_ms * (1 + 6 * max(0.0, sat - 0.75)) * (1 + g(0, 0.03))
                    if dep_down:
                        lat *= 3
                    cpu = min(100.0, 18 + 70 * min(sat, 1.2) + g(0, 1.5))
                err = min(1.0, max(0.0, err))
                for name, val in (("error_rate", err), ("latency_p95_ms", lat), ("cpu_pct", cpu),
                                  ("saturation", round(sat, 4)), ("requests_per_s", min(offered, a.capacity)),
                                  ("memory_pct", a.memory_pct + g(0, 0.5))):
                    sp = self.spike(a.id, name)
                    m(MetricSample(a.id, name, sp if sp is not None else val, now))
                if a.kind == "database":
                    lag_load = 1.0 + 4.0 * max(0.0, self.surge("db") - 1.0)
                    a.replication_lag_s = max(1.0, 2.0 * lag_load * a.internal + g(0, 0.3))
                    m(MetricSample(a.id, "replication_lag_s", a.replication_lag_s, now))
            if a.kind in ("host", "storage"):
                m(MetricSample(a.id, "disk_used_pct", a.disk_used_pct + g(0, 0.05), now))
            obs.configs[a.id] = copy.deepcopy(a.config)
            obs.open_ports[a.id] = sorted(a.open_ports)
        return obs

    # ------------------------------------------------------------------ adapter
    def apply_valve(self, asset_id: str, kind: str, position: float) -> None:
        a = self.assets.get(asset_id)
        if a is None:
            return
        if kind == "ingress":
            a.ingress = position
        else:
            a.internal = position

    def health(self, asset_id: str) -> bool | None:
        a = self.assets.get(asset_id)
        return None if a is None else (a.up and not a.isolated)

    def execute(self, req: ActionRequest) -> ActionResult:
        self.action_log.append(req)
        a = self.assets.get(req.target)
        k = req.kind
        if k == "package.upgrade":
            asset = self.inventory.get(req.target)
            for sw in asset.software if asset else []:
                if sw.name == req.params.get("package"):
                    old = sw.version
                    sw.version = str(req.params.get("version") or "latest")
                    return ActionResult(req.id, k, req.target, True, f"{sw.name} {old} -> {sw.version}",
                                        rollback={"package": sw.name, "version": old})
            return ActionResult(req.id, k, req.target, False, "package not installed")
        if k == "cert.renew":
            asset = self.inventory.get(req.target)
            for c in asset.certificates if asset else []:
                if c.name == req.params.get("cert") or not req.params.get("cert"):
                    c.expires_at = self.clock_now + 90 * 86400
            return ActionResult(req.id, k, req.target, True, "certificate renewed for 90 days")
        if a is None:
            return ActionResult(req.id, k, req.target, False, f"unknown asset {req.target}")
        if k == "service.restart":
            a.restarts += 1
            loop = any(f.active and f.kind == "crash_loop" and f.asset == a.id for f in self.faults)
            for f in self.faults:
                if f.active and f.kind == "crash" and f.asset == a.id:
                    f.active, f.cleared = False, True
            a.up = not loop
            return ActionResult(req.id, k, req.target, True,
                                "restarted" + (" (process exited again)" if loop else ""))
        if k == "service.scale_out":
            prev = a.replicas
            a.replicas += int(req.params.get("replicas", 1))
            return ActionResult(req.id, k, req.target, True, f"replicas {prev} -> {a.replicas}",
                                rollback={"replicas": prev})
        if k == "config.restore_baseline":
            b = self.baselines.get(req.target) if self.baselines else None
            if b is None:
                return ActionResult(req.id, k, req.target, False, "no baseline recorded")
            prev = copy.deepcopy(a.config)
            a.config = copy.deepcopy(b.config)
            for f in self.faults:
                if f.kind == "config_tamper" and f.asset == a.id:
                    f.cleared, f.active = True, False
            return ActionResult(req.id, k, req.target, True, "configuration restored to baseline v%d" % b.version,
                                rollback={"config": prev})
        if k == "storage.cleanup":
            before = a.disk_used_pct
            a.disk_used_pct = max(30.0, a.disk_used_pct - 25.0)
            for f in self.faults:
                if f.kind == "disk_leak" and f.asset == a.id and f.params.get("fixed_by_cleanup", True):
                    f.cleared, f.active = True, False
            return ActionResult(req.id, k, req.target, True, f"disk {before:.1f}% -> {a.disk_used_pct:.1f}%")
        if k == "storage.expand":
            before = a.disk_used_pct
            a.disk_used_pct = a.disk_used_pct / (1 + float(req.params.get("grow_pct", 50)) / 100)
            return ActionResult(req.id, k, req.target, True, f"volume grown; {before:.1f}% -> {a.disk_used_pct:.1f}%")
        if k == "network.block_port":
            port = int(req.params.get("port"))
            if port in a.open_ports:
                a.open_ports.remove(port)
            for f in self.faults:
                if f.kind == "open_port" and f.asset == a.id and f.params.get("port") == port:
                    f.cleared, f.active = True, False
            return ActionResult(req.id, k, req.target, True, f"port {port} blocked", rollback={"port": port})
        if k == "host.isolate":
            a.isolated = True
            for f in self.faults:
                if f.kind == "ransomware" and f.asset == a.id:
                    f.cleared, f.active = True, False
            return ActionResult(req.id, k, req.target, True, "host isolated from network", rollback={"isolated": False})
        return ActionResult(req.id, k, req.target, False, f"simulator does not implement {k}")

    def rollback(self, result: ActionResult) -> ActionResult:
        a = self.assets.get(result.target)
        rb = result.rollback or {}
        if result.kind == "service.scale_out" and a:
            a.replicas = rb.get("replicas", a.replicas)
        elif result.kind == "config.restore_baseline" and a and "config" in rb:
            a.config = rb["config"]
        elif result.kind == "network.block_port" and a:
            a.open_ports.append(rb["port"])
        elif result.kind == "host.isolate" and a:
            a.isolated = False
        return ActionResult(result.action_id, result.kind + ".rollback", result.target, True, "rolled back")
