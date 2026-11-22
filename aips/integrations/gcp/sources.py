"""Google Cloud telemetry for AIPS.

One collection cycle produces an ``Observation`` from:

* **Compute Engine state** - VM status; a MIG is "up" when all its members run and its uptime check passes;
* **Cloud Monitoring** - CPU (``compute.googleapis.com/instance/cpu/utilization``), and, when the Ops Agent is
  installed, memory and disk usage; uptime checks (``monitoring.googleapis.com/uptime_check/check_passed``);
* **firewall rules** - recorded as each network's configuration (drift detection) and turned into the set of
  internet-exposed ports per VM (exposure detection);
* **Cloud Audit Logs** - every admin / data-access call becomes an access event for the identity guard
  (who, which method, which resource, from which IP, success or failure);
* **Security Command Center** - active findings become external alerts.

Each part is independent: a missing permission or disabled API disables that part only and is reported in
``errors``; the rest of the cycle continues.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Callable

from ...telemetry.sources import MetricSample, Observation, TelemetrySource
from .client import LOGGING, MONITORING, SCC, GcpClient
from .discovery import GcpDiscovery, GcpTopology, exposed_ports, firewall_config, managed_by_aips

METRICS = {
    "compute.googleapis.com/instance/cpu/utilization": ("cpu_pct", 100.0, ""),
    "agent.googleapis.com/memory/percent_used": ("memory_pct", 1.0, 'metric.labels.state = "used"'),
    "agent.googleapis.com/disk/percent_used": ("disk_used_pct", 1.0, 'metric.labels.state = "used"'),
}
SERVICE_ALIASES = {"secretmanager": "secrets", "cloudkms": "kms", "cloudresourcemanager": "resourcemanager"}
SCC_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def rfc3339(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(s: str) -> float:
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()


def normalize_action(service: str, method: str) -> str:
    """'iam.googleapis.com' + 'google.iam.admin.v1.CreateServiceAccountKey' -> 'iam.createserviceaccountkey';
    'storage.googleapis.com' + 'storage.objects.get' -> 'storage.objects.get'."""
    svc = (service or "").split(".")[0].lower()
    svc = SERVICE_ALIASES.get(svc, svc)
    parts = [p for p in re.split(r"[./]", method or "") if p and p.lower() != "google"
             and not re.fullmatch(r"v\d+(beta\d*|alpha\d*)?", p.lower())]
    if parts and parts[0].lower() == svc:
        parts = parts[1:]
    tail = parts[-2:] if len(parts) >= 2 and parts[-1][:1].islower() else parts[-1:]
    return ".".join([svc] + [p.lower() for p in tail]) if tail else svc


class GcpTelemetrySource(TelemetrySource):
    name = "gcp"

    def __init__(self, client: GcpClient, uptime_checks: dict[str, str] | None = None, window_s: float = 600,
                 refresh_topology_s: float = 25, audit_logs: bool = True, scc: bool = True,
                 monitoring: bool = True, clock: Callable[[], float] = time.time):
        self.c = client
        self.uptime_checks = uptime_checks or {}           # uptime check id -> asset id
        self.window_s = window_s
        self.refresh_s = refresh_topology_s
        self.audit_logs, self.scc, self.monitoring = audit_logs, scc, monitoring
        self.clock = clock
        self.topology: GcpTopology | None = None
        self._topo_at = 0.0
        self._audit_since: float | None = None
        self._seen_findings: set[str] = set()
        self.errors: dict[str, str] = {}
        self.stats = {"access_events": 0, "scc_findings": 0, "metric_points": 0}

    # ------------------------------------------------------------------ parts
    def _topo(self, now: float) -> GcpTopology:
        if self.topology is None or now - self._topo_at >= self.refresh_s:
            self.topology = GcpDiscovery(self.c).topology()
            self._topo_at = now
        return self.topology

    def _series(self, metric: str, extra: str, now: float) -> list[dict[str, Any]]:
        flt = f'metric.type = "{metric}"' + (f" AND {extra}" if extra else "")
        params = {"filter": flt, "interval.startTime": rfc3339(now - self.window_s),
                  "interval.endTime": rfc3339(now), "aggregation.alignmentPeriod": "60s",
                  "aggregation.perSeriesAligner": "ALIGN_MEAN" if "uptime" not in metric else "ALIGN_FRACTION_TRUE"}
        return list(self.c.pages(f"{MONITORING}/projects/{self.c.project}/timeSeries", "timeSeries", **params))

    @staticmethod
    def _latest(ts: dict[str, Any]) -> float | None:
        pts = ts.get("points") or []
        if not pts:
            return None
        v = pts[0].get("value", {})          # the API returns newest point first
        for k in ("doubleValue", "int64Value", "boolValue"):
            if k in v:
                return float(v[k])
        return None

    def _metrics(self, obs: Observation, topo: GcpTopology, now: float) -> None:
        per_mig: dict[str, dict[str, list[float]]] = {}
        for metric, (name, scale, extra) in METRICS.items():
            best: dict[str, float] = {}
            for ts in self._series(metric, extra, now):
                inst = topo.instance_by_id(ts.get("resource", {}).get("labels", {}).get("instance_id", ""))
                v = self._latest(ts)
                if inst is None or v is None:
                    continue
                best[inst.name] = max(best.get(inst.name, float("-inf")), v * scale)
            for iname, v in best.items():
                obs.metrics.append(MetricSample(iname, name, v, now))
                self.stats["metric_points"] += 1
                mig = topo.instances[iname].mig
                if mig:
                    per_mig.setdefault(mig, {}).setdefault(name, []).append(v)
        for mig, vals in per_mig.items():
            for name, vs in vals.items():
                obs.metrics.append(MetricSample(mig, name, sum(vs) / len(vs), now))
        for ts in self._series("monitoring.googleapis.com/uptime_check/check_passed", "", now):
            check = ts.get("metric", {}).get("labels", {}).get("check_id", "")
            asset = self.uptime_checks.get(check)
            frac = self._latest(ts)
            if asset and frac is not None:
                # several checker regions report; the asset is up only if they agree it passes
                prev = obs.service_up.get(asset, True)
                obs.service_up[asset] = prev and frac >= 0.5
                obs.metrics.append(MetricSample(asset, "uptime_pass_fraction", frac, now))

    def _audit(self, obs: Observation, now: float) -> None:
        since = self._audit_since if self._audit_since is not None else now - self.window_s
        flt = (f'logName:"cloudaudit.googleapis.com" AND protoPayload.authenticationInfo.principalEmail:* '
               f'AND timestamp > "{rfc3339(since)}"')
        newest = since
        for e in self.c.pages(f"{LOGGING}/entries:list", "entries", method="POST",
                              body={"resourceNames": [f"projects/{self.c.project}"], "filter": flt,
                                    "orderBy": "timestamp asc", "pageSize": 500}):
            p = e.get("protoPayload", {})
            who = p.get("authenticationInfo", {}).get("principalEmail")
            if not who:
                continue
            ts = parse_ts(e.get("timestamp", rfc3339(now)))
            newest = max(newest, ts)
            obs.events.append({
                "type": "access", "identity": who,
                "action": normalize_action(p.get("serviceName", ""), p.get("methodName", "")),
                "resource": p.get("resourceName", ""), "source_ip": p.get("requestMetadata", {}).get("callerIp"),
                "success": int(p.get("status", {}).get("code", 0) or 0) == 0, "ts": ts,
                "session": None})
            self.stats["access_events"] += 1
        self._audit_since = newest

    def _scc(self, obs: Observation, topo: GcpTopology) -> None:
        url = f"{SCC}/projects/{self.c.project}/sources/-/locations/global/findings"
        for r in self.c.pages(url, "listFindingsResults", filter='state="ACTIVE"'):
            f = r.get("finding", {})
            if not f.get("name") or f["name"] in self._seen_findings:
                continue
            self._seen_findings.add(f["name"])
            res = f.get("resourceName", "")
            asset = res.rsplit("/", 1)[-1]
            inst = topo.instance_by_id(asset) or topo.instances.get(asset)
            obs.events.append({
                "type": "alert", "source": "gcp-scc", "asset": inst.name if inst else f"gcp:{asset}",
                "severity": SCC_SEVERITY.get(f.get("severity", ""), "MEDIUM"), "category": "security",
                "signal": f"scc:{f.get('category', 'finding').lower()}", "confidence": 0.85,
                "title": f"Security Command Center: {f.get('category', 'finding')} on {res}", "key": f["name"]})
            self.stats["scc_findings"] += 1

    # ------------------------------------------------------------------ main
    def collect(self, now: float) -> Observation:
        obs = Observation(ts=now)
        try:
            topo = self._topo(now)
        except Exception as exc:  # noqa: BLE001 - without topology nothing else can be mapped
            self.errors["topology"] = repr(exc)
            return obs
        self.errors.pop("topology", None)
        for name, i in topo.instances.items():
            obs.open_ports[name] = exposed_ports(i, topo.firewalls)
        for name, m in topo.migs.items():
            obs.service_up[m.name] = bool(m.instances) and all(
                topo.instances.get(n) is not None and topo.instances[n].status == "RUNNING" for n in m.instances)
            obs.metrics.append(MetricSample(name, "replicas", float(m.target_size), now))
        # firewall configuration as drift-relevant state: enabled rules only (a disabled rule has no effect),
        # and never AIPS's own containment rules (otherwise AIPS would chase its own changes)
        nets: dict[str, dict[str, Any]] = {}
        for r in topo.firewalls:
            net = f"net-{r.get('network', '').rsplit('/', 1)[-1]}"
            nets.setdefault(net, {})
            if not r.get("disabled") and not managed_by_aips(r["name"]):
                nets[net][r["name"]] = firewall_config(r)
        obs.configs.update(nets)
        for part, enabled, fn in (("monitoring", self.monitoring, lambda: self._metrics(obs, topo, now)),
                                  ("audit_logs", self.audit_logs, lambda: self._audit(obs, now)),
                                  ("scc", self.scc, lambda: self._scc(obs, topo))):
            if not enabled:
                continue
            try:
                fn()
                self.errors.pop(part, None)
            except Exception as exc:  # noqa: BLE001 - one missing API must not blind the others
                self.errors[part] = repr(exc)
        return obs
