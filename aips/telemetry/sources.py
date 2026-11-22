"""Telemetry sources feeding the Level 1 fleet.

A source returns an ``Observation`` per collection cycle: metric samples,
service states, configuration snapshots, open ports and discrete events.
Sources included:

* ``HostTelemetrySource``  - real measurements of the local machine using only
  the standard library (disk usage, load average, TCP/HTTP health probes,
  configuration file fingerprints).
* ``JsonlTelemetrySource`` - replays/ingests observations written by any
  external agent (Prometheus exporter bridge, Fluent Bit, custom scripts).
* ``aips.sim.environment.SimulatedInfrastructure`` - the simulator.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MetricSample:
    asset_id: str
    metric: str
    value: float
    ts: float


@dataclass
class Observation:
    ts: float
    metrics: list[MetricSample] = field(default_factory=list)
    service_up: dict[str, bool] = field(default_factory=dict)
    configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def metric(self, asset_id: str, name: str) -> float | None:
        for m in self.metrics:
            if m.asset_id == asset_id and m.metric == name:
                return m.value
        return None

    def merge(self, other: "Observation") -> "Observation":
        self.metrics.extend(other.metrics)
        self.service_up.update(other.service_up)
        self.configs.update(other.configs)
        self.open_ports.update(other.open_ports)
        self.events.extend(other.events)
        return self


class TelemetrySource:
    name = "source"

    def collect(self, now: float) -> Observation:  # pragma: no cover - interface
        raise NotImplementedError


class HostTelemetrySource(TelemetrySource):
    """Real, dependency-free measurements of the host AIPS runs on.

    ``probes`` maps an asset id to a probe definition::

        {"type": "tcp", "host": "127.0.0.1", "port": 5432}
        {"type": "http", "url": "http://127.0.0.1:8080/healthz", "expect": 200}

    ``config_files`` maps an asset id to a list of files whose content hashes
    form the asset's configuration snapshot (used for drift detection).
    """

    name = "host"

    def __init__(self, asset_id: str, disk_paths: list[str] | None = None,
                 probes: dict[str, dict[str, Any]] | None = None,
                 config_files: dict[str, list[str]] | None = None, timeout: float = 2.0):
        self.asset_id = asset_id
        self.disk_paths = disk_paths or [os.path.abspath(os.sep)]
        self.probes = probes or {}
        self.config_files = config_files or {}
        self.timeout = timeout

    def _probe(self, spec: dict[str, Any]) -> tuple[bool, float]:
        import time
        t0 = time.perf_counter()
        try:
            if spec["type"] == "tcp":
                with socket.create_connection((spec["host"], int(spec["port"])), timeout=self.timeout):
                    pass
                ok = True
            elif spec["type"] == "http":
                req = urllib.request.Request(spec["url"], headers={"User-Agent": "aips-probe/1.0"})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - operator configured
                    ok = resp.status == int(spec.get("expect", 200))
            else:
                ok = False
        except (OSError, urllib.error.URLError, ValueError):
            ok = False
        return ok, (time.perf_counter() - t0) * 1000.0

    def collect(self, now: float) -> Observation:
        obs = Observation(ts=now)
        for p in self.disk_paths:
            try:
                du = shutil.disk_usage(p)
                obs.metrics.append(MetricSample(self.asset_id, "disk_used_pct", 100.0 * du.used / du.total, now))
            except OSError:
                pass
        if hasattr(os, "getloadavg"):
            try:
                l1, _, _ = os.getloadavg()
                obs.metrics.append(MetricSample(self.asset_id, "load1_per_cpu", l1 / (os.cpu_count() or 1), now))
            except OSError:
                pass
        for asset_id, spec in self.probes.items():
            ok, ms = self._probe(spec)
            obs.service_up[asset_id] = ok
            obs.metrics.append(MetricSample(asset_id, "probe_latency_ms", ms, now))
        for asset_id, files in self.config_files.items():
            snap: dict[str, Any] = {}
            for f in files:
                try:
                    snap[f] = hashlib.sha256(Path(f).read_bytes()).hexdigest()
                except OSError:
                    snap[f] = None
            obs.configs[asset_id] = snap
        return obs


class JsonlTelemetrySource(TelemetrySource):
    """Tails a JSON-lines file. Each line is one of::

        {"type": "metric", "asset": "api", "metric": "error_rate", "value": 0.02}
        {"type": "service", "asset": "api", "up": true}
        {"type": "config", "asset": "api", "config": {...}}
        {"type": "ports", "asset": "api", "ports": [443]}
        {"type": "event", ...}
    """

    name = "jsonl"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._offset = 0

    def collect(self, now: float) -> Observation:
        obs = Observation(ts=now)
        if not self.path.exists():
            return obs
        with self.path.open("r", encoding="utf-8") as fh:
            fh.seek(self._offset)
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                t = rec.get("type")
                ts = float(rec.get("ts", now))
                if t == "metric":
                    obs.metrics.append(MetricSample(rec["asset"], rec["metric"], float(rec["value"]), ts))
                elif t == "service":
                    obs.service_up[rec["asset"]] = bool(rec["up"])
                elif t == "config":
                    obs.configs[rec["asset"]] = dict(rec["config"])
                elif t == "ports":
                    obs.open_ports[rec["asset"]] = [int(p) for p in rec["ports"]]
                else:
                    obs.events.append(rec)
            self._offset = fh.tell()
        return obs
