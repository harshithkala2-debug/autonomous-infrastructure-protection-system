"""Level 1 detection bots.

Each detector is a small, specialised bot that inspects one kind of signal and
emits ``Finding`` objects. Detectors never act; they only report. Severity is
adjusted for asset criticality so that the same symptom on a business-critical
asset is weighted more heavily.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from ..core.models import Category, Evidence, Finding, Severity
from ..repair.baseline import DesiredStateStore
from ..telemetry.inventory import Inventory
from ..telemetry.sources import Observation


class MetricHistory:
    """Bounded per-(asset, metric) time series kept for trend detectors."""

    def __init__(self, maxlen: int = 720):
        self._series: dict[tuple[str, str], deque[tuple[float, float]]] = defaultdict(lambda: deque(maxlen=maxlen))

    def add(self, asset_id: str, metric: str, ts: float, value: float) -> None:
        self._series[(asset_id, metric)].append((ts, value))

    def series(self, asset_id: str, metric: str) -> list[tuple[float, float]]:
        return list(self._series.get((asset_id, metric), ()))


@dataclass
class DetectionContext:
    inventory: Inventory
    baselines: DesiredStateStore
    history: MetricHistory
    now: float


def adjust_for_criticality(sev: Severity, criticality: int) -> Severity:
    if criticality >= 5:
        return sev.bump(1)
    if criticality <= 1:
        return sev.bump(-1)
    return sev


class Detector:
    name = "detector"
    category = Category.AVAILABILITY

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def _finding(self, ctx: DetectionContext, asset_id: str, sev: Severity, conf: float, title: str,
                 signal: str, evidence: list[Evidence], category: Category | None = None,
                 description: str = "", tags: dict[str, str] | None = None, adjust: bool = True) -> Finding:
        if adjust:
            sev = adjust_for_criticality(sev, ctx.inventory.criticality(asset_id))
        return Finding(detector=self.name, category=category or self.category, severity=sev,
                       confidence=round(max(0.0, min(1.0, conf)), 3), asset_id=asset_id, title=title,
                       description=description, evidence=evidence, created_at=ctx.now, signal=signal,
                       tags=tags or {})


class HealthDetector(Detector):
    """Service liveness. Confidence grows with consecutive failed probes."""

    name = "l1.health"
    category = Category.AVAILABILITY

    def __init__(self) -> None:
        self._fails: dict[str, int] = defaultdict(int)

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for asset_id, up in obs.service_up.items():
            if up:
                self._fails[asset_id] = 0
                continue
            self._fails[asset_id] += 1
            n = self._fails[asset_id]
            conf = 1 - 0.35 ** n          # 0.65, 0.88, 0.96 ...
            out.append(self._finding(
                ctx, asset_id, Severity.HIGH, conf, f"{asset_id} is not responding",
                "service_down",
                [Evidence("health", self.name, {"up": False, "consecutive_failures": n}, obs.ts)],
                description=f"Health probe failed {n} consecutive time(s)."))
        return out


@dataclass
class ThresholdRule:
    metric: str
    op: str                         # > >= < <=
    value: float
    severity: Severity
    category: Category
    signal: str
    for_cycles: int = 1
    assets: list[str] | None = None  # None = all

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ThresholdRule":
        return cls(d["metric"], d.get("op", ">"), float(d["value"]), Severity.parse(d.get("severity", "MEDIUM")),
                   Category(d.get("category", "performance")), d.get("signal", f"threshold:{d['metric']}"),
                   int(d.get("for_cycles", 1)), d.get("assets"))

    def breached(self, v: float) -> bool:
        return {">": v > self.value, ">=": v >= self.value, "<": v < self.value, "<=": v <= self.value}[self.op]


DEFAULT_THRESHOLDS = [
    ThresholdRule("error_rate", ">", 0.05, Severity.MEDIUM, Category.AVAILABILITY, "error_rate_high", 2),
    ThresholdRule("error_rate", ">", 0.25, Severity.HIGH, Category.AVAILABILITY, "error_rate_critical", 1),
    ThresholdRule("latency_p95_ms", ">", 800, Severity.MEDIUM, Category.PERFORMANCE, "latency_high", 2),
    ThresholdRule("cpu_pct", ">", 90, Severity.MEDIUM, Category.CAPACITY, "cpu_saturated", 3),
    ThresholdRule("saturation", ">", 0.9, Severity.HIGH, Category.CAPACITY, "overload", 1),
    ThresholdRule("disk_used_pct", ">", 90, Severity.HIGH, Category.CAPACITY, "disk_full", 1),
    ThresholdRule("memory_pct", ">", 92, Severity.MEDIUM, Category.CAPACITY, "memory_pressure", 2),
    ThresholdRule("replication_lag_s", ">", 120, Severity.MEDIUM, Category.DATA_INTEGRITY, "replication_lag", 2),
]


class ThresholdDetector(Detector):
    name = "l1.threshold"

    def __init__(self, rules: list[ThresholdRule] | None = None):
        self.rules = rules if rules is not None else list(DEFAULT_THRESHOLDS)
        self._streak: dict[tuple[int, str], int] = defaultdict(int)

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for i, rule in enumerate(self.rules):
            seen = set()
            for m in obs.metrics:
                if m.metric != rule.metric or (rule.assets and m.asset_id not in rule.assets):
                    continue
                seen.add(m.asset_id)
                key = (i, m.asset_id)
                if rule.breached(m.value):
                    self._streak[key] += 1
                    if self._streak[key] >= rule.for_cycles:
                        margin = abs(m.value - rule.value) / (abs(rule.value) or 1.0)
                        conf = min(0.97, 0.6 + 0.1 * self._streak[key] + min(0.2, margin))
                        out.append(self._finding(
                            ctx, m.asset_id, rule.severity, conf,
                            f"{rule.metric} {rule.op} {rule.value:g} on {m.asset_id} ({m.value:.3g})",
                            rule.signal,
                            [Evidence("metric", self.name, {"metric": m.metric, "value": m.value,
                                                            "threshold": rule.value, "op": rule.op,
                                                            "cycles": self._streak[key]}, m.ts)],
                            category=rule.category))
                else:
                    self._streak[key] = 0
            for key in [k for k in self._streak if k[0] == i and k[1] not in seen]:
                self._streak[key] = 0
        return out


class AnomalyDetector(Detector):
    """Exponentially-weighted mean/variance z-score detector.

    Catches deviations that fixed thresholds miss. Anomalous points are folded
    into the model with a reduced weight so an ongoing incident does not
    immediately become "normal".
    """

    name = "l1.anomaly"
    category = Category.PERFORMANCE

    def __init__(self, metrics: list[str] | None = None, alpha: float = 0.1, z_threshold: float = 3.5,
                 warmup: int = 12, min_std: float = 1e-3, level_shift_after: int = 10):
        self.metrics = set(metrics or ["latency_p95_ms", "error_rate", "requests_per_s", "cpu_pct"])
        self.alpha, self.z, self.warmup, self.min_std = alpha, z_threshold, warmup, min_std
        self.level_shift_after = level_shift_after
        self._state: dict[tuple[str, str], list[float]] = {}   # mean, var, n
        self._streak: dict[tuple[str, str], int] = defaultdict(int)

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for m in obs.metrics:
            if m.metric not in self.metrics:
                continue
            key = (m.asset_id, m.metric)
            st = self._state.get(key)
            if st is None:
                self._state[key] = [m.value, 0.0, 1]
                continue
            mean, var, n = st
            std = max(math.sqrt(var), self.min_std, abs(mean) * 0.02)
            z = (m.value - mean) / std
            anomalous = n >= self.warmup and abs(z) >= self.z
            self._streak[key] = self._streak[key] + 1 if anomalous else 0
            if self._streak[key] >= self.level_shift_after:
                # sustained level shift (e.g. new capacity after scale-out): accept it as the new normal
                self._state[key] = [m.value, var, n + 1]
                self._streak[key] = 0
                continue
            a = self.alpha * (0.1 if anomalous else 1.0)
            diff = m.value - mean
            mean += a * diff
            var = (1 - a) * (var + a * diff * diff)
            self._state[key] = [mean, var, n + 1]
            if anomalous:
                sev = Severity.MEDIUM if abs(z) >= 2 * self.z else Severity.LOW
                conf = min(0.9, 0.35 + 0.08 * (abs(z) - self.z))
                out.append(self._finding(
                    ctx, m.asset_id, sev, conf, f"Anomalous {m.metric} on {m.asset_id} (z={z:.1f})",
                    f"anomaly:{m.metric}",
                    [Evidence("metric", self.name, {"metric": m.metric, "value": m.value,
                                                    "expected": round(mean, 4), "z": round(z, 2)}, m.ts)],
                    tags={"key": m.metric}))
        return out


class CapacityForecastDetector(Detector):
    """Least-squares trend on a usage metric; warns before the resource is exhausted.

    This is the "catch small issues before they grow" bot: it fires while
    usage is still well below any hard threshold.
    """

    name = "l1.forecast"
    category = Category.CAPACITY

    def __init__(self, metric: str = "disk_used_pct", limit: float = 100.0, horizon_s: float = 6 * 3600,
                 min_points: int = 6, window: int = 30):
        self.metric, self.limit, self.horizon, self.min_points, self.window = metric, limit, horizon_s, min_points, window

    @staticmethod
    def _fit(points: list[tuple[float, float]]) -> tuple[float, float, float]:
        n = len(points)
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        mx, my = sum(xs) / n, sum(ys) / n
        sxx = sum((x - mx) ** 2 for x in xs)
        if sxx == 0:
            return 0.0, my, 0.0
        sxy = sum((x - mx) * (y - my) for x, y in points)
        slope = sxy / sxx
        icpt = my - slope * mx
        ss_tot = sum((y - my) ** 2 for y in ys)
        ss_res = sum((y - (slope * x + icpt)) ** 2 for x, y in points)
        r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 0.0
        return slope, icpt, r2

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for m in obs.metrics:
            if m.metric != self.metric:
                continue
            pts = ctx.history.series(m.asset_id, self.metric)[-self.window:]
            if len(pts) < self.min_points:
                continue
            slope, _, r2 = self._fit(pts)
            if slope <= 0 or r2 < 0.6:
                continue
            ttf = (self.limit - m.value) / slope
            if ttf <= 0 or ttf > self.horizon:
                continue
            sev = Severity.HIGH if ttf < 3600 else Severity.MEDIUM if ttf < 3 * 3600 else Severity.LOW
            out.append(self._finding(
                ctx, m.asset_id, sev, min(0.95, 0.5 + 0.45 * r2),
                f"{self.metric} on {m.asset_id} projected to reach {self.limit:g} in {ttf / 60:.0f} min",
                "disk_forecast" if "disk" in self.metric else f"forecast:{self.metric}",
                [Evidence("trend", self.name, {"metric": self.metric, "current": m.value,
                                               "slope_per_hour": slope * 3600, "r2": round(r2, 3),
                                               "time_to_limit_s": round(ttf)}, m.ts)]))
        return out


class DriftDetector(Detector):
    """Compares live configuration with the recorded known-good baseline."""

    name = "l1.drift"
    category = Category.CONFIGURATION

    def __init__(self, store: DesiredStateStore):
        self.store = store

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for asset_id, cfg in obs.configs.items():
            diffs = self.store.compare_config(asset_id, cfg)
            if not diffs:
                continue
            sensitive = [d for d in diffs if d.security_sensitive]
            sev = Severity.HIGH if sensitive else Severity.MEDIUM
            out.append(self._finding(
                ctx, asset_id, sev, 0.95,
                f"Configuration drift on {asset_id}: {len(diffs)} change(s)"
                + (f", {len(sensitive)} security-sensitive" if sensitive else ""),
                "config_drift",
                [Evidence("config_diff", self.name,
                          {"diffs": [{"path": d.path, "expected": d.expected, "actual": d.actual,
                                      "change": d.change, "security_sensitive": d.security_sensitive}
                                     for d in diffs]}, obs.ts)],
                category=Category.SECURITY if sensitive else Category.CONFIGURATION,
                tags={"security_sensitive": str(bool(sensitive)).lower()}))
        return out


class PortExposureDetector(Detector):
    name = "l1.exposure"
    category = Category.SECURITY

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for asset_id, ports in obs.open_ports.items():
            asset = ctx.inventory.get(asset_id)
            if asset is None or not asset.allowed_ports:
                continue
            extra = sorted(set(ports) - set(asset.allowed_ports))
            for p in extra:
                out.append(self._finding(
                    ctx, asset_id, Severity.HIGH, 0.9, f"Unexpected open port {p} on {asset_id}",
                    "unexpected_port",
                    [Evidence("ports", self.name, {"port": p, "allowed": asset.allowed_ports, "open": ports}, obs.ts)],
                    tags={"key": str(p), "port": str(p)}))
        return out


class CertificateExpiryDetector(Detector):
    name = "l1.certs"
    category = Category.AVAILABILITY

    def __init__(self, warn_days: float = 30, critical_days: float = 7):
        self.warn, self.crit = warn_days * 86400, critical_days * 86400

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for asset in ctx.inventory:
            for cert in asset.certificates:
                left = cert.expires_at - ctx.now
                if left > self.warn:
                    continue
                sev = Severity.CRITICAL if left <= 0 else Severity.HIGH if left <= self.crit else Severity.MEDIUM
                out.append(self._finding(
                    ctx, asset.id, sev, 0.99,
                    f"Certificate '{cert.name}' on {asset.id} "
                    + ("has expired" if left <= 0 else f"expires in {left / 86400:.1f} days"),
                    "cert_expiry",
                    [Evidence("certificate", self.name, {"name": cert.name, "expires_at": cert.expires_at,
                                                         "seconds_left": round(left)}, ctx.now)],
                    tags={"key": cert.name, "cert": cert.name}, adjust=False))
        return out


class ExternalAlertDetector(Detector):
    """Adapts alerts from existing tools (IDS, EDR, cloud security posture) into findings.

    Event shape: ``{"type": "alert", "asset": ..., "severity": "HIGH", "category": "security",
    "signal": "...", "title": "...", "confidence": 0.8}``
    """

    name = "l1.external"

    def detect(self, obs: Observation, ctx: DetectionContext) -> list[Finding]:
        out = []
        for ev in obs.events:
            if ev.get("type") != "alert":
                continue
            out.append(self._finding(
                ctx, ev["asset"], Severity.parse(ev.get("severity", "MEDIUM")), float(ev.get("confidence", 0.7)),
                ev.get("title", "external alert"), ev.get("signal", "external_alert"),
                [Evidence("alert", ev.get("source", self.name), dict(ev), obs.ts)],
                category=Category(ev.get("category", "security")), tags={"key": str(ev.get("key", ""))}))
        return out


@dataclass
class DetectorStats:
    runs: int = 0
    findings: int = 0
    errors: int = 0
    last_error: str = ""


@dataclass
class Level1Fleet:
    detectors: list[Detector]
    history: MetricHistory = field(default_factory=MetricHistory)
    stats: dict[str, DetectorStats] = field(default_factory=lambda: defaultdict(DetectorStats))

    def run(self, obs: Observation, inventory: Inventory, baselines: DesiredStateStore, now: float) -> list[Finding]:
        for m in obs.metrics:
            self.history.add(m.asset_id, m.metric, m.ts, m.value)
        ctx = DetectionContext(inventory, baselines, self.history, now)
        findings: list[Finding] = []
        for d in self.detectors:
            st = self.stats[d.name]
            st.runs += 1
            try:
                got = d.detect(obs, ctx)
            except Exception as exc:  # noqa: BLE001 - one broken bot must not blind the fleet
                st.errors += 1
                st.last_error = repr(exc)
                continue
            for f in got:
                f.route.append(1)
            st.findings += len(got)
            findings.extend(got)
        return findings


def default_fleet(baselines: DesiredStateStore, thresholds: list[ThresholdRule] | None = None) -> Level1Fleet:
    return Level1Fleet([
        HealthDetector(),
        ThresholdDetector(thresholds),
        AnomalyDetector(),
        CapacityForecastDetector(),
        DriftDetector(baselines),
        PortExposureDetector(),
        CertificateExpiryDetector(),
        ExternalAlertDetector(),
    ])
