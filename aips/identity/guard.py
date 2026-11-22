"""Identity and access protection (concept section 4).

* Each identity (human, service, application) has a ``PermissionBoundary``:
  what it may do, on which resources, from which networks, at which hours,
  at what rate. Requests outside the boundary are denied (least privilege).
* A ``BehaviorProfile`` is learned from *legitimate* activity only (risky
  events are never learned, so an attacker cannot train the profile).
* Each access event gets a risk score (noisy-OR of independent indicators).
  Unusual-but-permitted activity is allowed and reported at low severity;
  only accumulated or strong evidence becomes a finding that the evaluation
  hierarchy may turn into a freeze. Unusual is not treated as malicious.
* Freezes are executed by Level 3 through the authorisation policy and are
  always appealable: a legitimate user/administrator files an appeal and a
  human reviewer can restore access, teaching the profile at the same time.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from ..core.models import Category, Evidence, Finding, Severity, new_id

SENSITIVE_ACTIONS = ("iam.*", "*.delete", "secrets.*", "kms.*", "*.export", "billing.*", "audit.disable")


@dataclass
class Identity:
    id: str
    kind: str = "human"                 # human | service | application
    owner: str = ""
    roles: list[str] = field(default_factory=list)


@dataclass
class PermissionRule:
    action: str                          # glob, e.g. "storage.read"
    resource: str = "*"                  # glob, e.g. "bucket/reports/*"

    def matches(self, action: str, resource: str) -> bool:
        return fnmatch.fnmatch(action, self.action) and fnmatch.fnmatch(resource, self.resource)


@dataclass
class PermissionBoundary:
    allow: list[PermissionRule] = field(default_factory=list)
    deny: list[PermissionRule] = field(default_factory=list)
    source_networks: list[str] = field(default_factory=list)       # CIDRs; empty = any
    allowed_hours_utc: tuple[int, int] | None = None               # [start, end) hours; wraps midnight
    max_rate_per_min: int | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PermissionBoundary":
        def rules(x):
            return [PermissionRule(**r) if isinstance(r, dict) else PermissionRule(r) for r in x]
        hours = d.get("allowed_hours_utc")
        return cls(rules(d.get("allow", [])), rules(d.get("deny", [])), list(d.get("source_networks", [])),
                   tuple(hours) if hours else None, d.get("max_rate_per_min"))

    def permits(self, action: str, resource: str) -> tuple[bool, str]:
        for r in self.deny:
            if r.matches(action, resource):
                return False, f"explicitly denied by rule {r.action} on {r.resource}"
        for r in self.allow:
            if r.matches(action, resource):
                return True, ""
        return False, f"{action} on {resource} is outside the permission boundary"

    def network_ok(self, ip: str | None) -> bool:
        if not self.source_networks or not ip:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(n, strict=False) for n in self.source_networks)

    def hour_ok(self, hour: int) -> bool:
        if not self.allowed_hours_utc:
            return True
        s, e = self.allowed_hours_utc
        return s <= hour < e if s <= e else (hour >= s or hour < e)


@dataclass
class AccessEvent:
    identity_id: str
    action: str
    resource: str
    ts: float
    source_ip: str | None = None
    success: bool = True                 # False = failed authentication / authorisation at the source
    session_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)   # platform detail, e.g. what a call created


@dataclass
class ActionRecord:
    """What an identity did, as reported by the platform (kept so a freeze can be followed by a revert)."""

    ts: float
    action: str
    resource: str
    source_ip: str | None
    success: bool
    flagged: bool                        # judged risky (finding raised, denied, or after the identity was frozen)
    details: dict[str, Any]


@dataclass
class AccessDecision:
    allowed: bool
    risk: float
    reasons: list[str]
    finding: Finding | None = None


def _net_key(ip: str | None) -> str:
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


@dataclass
class BehaviorProfile:
    events: int = 0
    hours: list[int] = field(default_factory=lambda: [0] * 24)
    actions: Counter = field(default_factory=Counter)
    resources: Counter = field(default_factory=Counter)
    networks: Counter = field(default_factory=Counter)
    rate_ewma: float = 0.0

    def learn(self, ev: AccessEvent, hour: int, rate: float) -> None:
        self.events += 1
        self.hours[hour] += 1
        self.actions[ev.action] += 1
        self.resources[_resource_prefix(ev.resource)] += 1
        self.networks[_net_key(ev.source_ip)] += 1
        self.rate_ewma = rate if self.events == 1 else 0.9 * self.rate_ewma + 0.1 * rate


def _resource_prefix(resource: str) -> str:
    parts = resource.split("/")
    return "/".join(parts[:2]) if len(parts) > 1 else resource


class AppealStatus(str, Enum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"


@dataclass
class Appeal:
    identity_id: str
    submitted_by: str
    reason: str
    submitted_at: float
    status: AppealStatus = AppealStatus.PENDING
    reviewer: str | None = None
    reviewed_at: float | None = None
    note: str = ""
    id: str = field(default_factory=lambda: new_id("APL"))


@dataclass
class GuardConfig:
    learn_min_events: int = 20
    anomaly_report_risk: float = 0.45
    high_risk: float = 0.75
    failure_burst: int = 5
    failure_window_s: float = 300.0
    anomaly_accumulation: int = 3
    anomaly_window_s: float = 900.0
    # cloud audit logs contain principals nobody registered; "learn" registers them on first sight with an
    # unrestricted boundary so they are judged by behaviour (profile, failures, sensitive actions) instead of
    # being treated as violations. Tighten real boundaries in configuration over time.
    auto_register_unknown: bool = False


class IdentityGuard:
    name = "id.guard"

    def __init__(self, config: GuardConfig | None = None,
                 on_false_positive: Callable[[str], None] | None = None):
        self.config = config or GuardConfig()
        self.identities: dict[str, Identity] = {}
        self.boundaries: dict[str, PermissionBoundary] = {}
        self.profiles: dict[str, BehaviorProfile] = defaultdict(BehaviorProfile)
        self.frozen: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, set[str]] = defaultdict(set)
        self.revoked_sessions: set[str] = set()
        self.appeals: dict[str, Appeal] = {}
        self._recent: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=1000))
        self._failures: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=200))
        self._anomalies: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=50))
        self._exceptions: dict[str, set[tuple[str, str]]] = defaultdict(set)
        self.history: dict[str, deque[ActionRecord]] = defaultdict(lambda: deque(maxlen=2000))
        self.on_false_positive = on_false_positive
        self._lock = threading.RLock()
        self.stats = Counter()

    # -- registration ----------------------------------------------------------
    def register(self, identity: Identity, boundary: PermissionBoundary) -> None:
        self.identities[identity.id] = identity
        self.boundaries[identity.id] = boundary

    def is_frozen(self, identity_id: str) -> bool:
        return identity_id in self.frozen

    # -- evaluation --------------------------------------------------------------
    def evaluate(self, ev: AccessEvent) -> AccessDecision:
        with self._lock:
            dec = self._evaluate(ev)
            # the platform already executed this call if it succeeded there; remember it for a possible revert
            self.history[ev.identity_id].append(ActionRecord(
                ev.ts, ev.action, ev.resource, ev.source_ip, ev.success,
                flagged=dec.finding is not None or not dec.allowed, details=dict(ev.details)))
            return dec

    def suspicious_actions(self, identity_id: str, since: float | None = None) -> list[ActionRecord]:
        """Successful platform actions of an identity from its first flagged action onward.

        Anything an identity did after it first behaved suspiciously is treated as possibly attacker-driven;
        legitimate work done before that point is left alone."""
        recs = [r for r in self.history.get(identity_id, ()) if since is None or r.ts >= since]
        first = next((r.ts for r in recs if r.flagged), None)
        if first is None:
            return []
        return [r for r in recs if r.ts >= first and r.success]

    def _evaluate(self, ev: AccessEvent) -> AccessDecision:
        cfg = self.config
        self.stats["events"] += 1
        iid = ev.identity_id
        if iid in self.frozen:
            self.stats["denied_frozen"] += 1
            return AccessDecision(False, 1.0, ["identity is frozen pending review"])
        if ev.session_id and ev.session_id in self.revoked_sessions:
            self.stats["denied_revoked"] += 1
            return AccessDecision(False, 1.0, ["session was revoked"])

        boundary = self.boundaries.get(iid)
        if boundary is None and cfg.auto_register_unknown:
            self.register(Identity(iid, "service" if iid.endswith(".gserviceaccount.com") else "human"),
                          PermissionBoundary(allow=[PermissionRule("*", "*")]))
            boundary = self.boundaries[iid]
            self.stats["auto_registered"] += 1
        hour = int((ev.ts // 3600) % 24)
        recent = self._recent[iid]
        recent.append(ev.ts)
        while recent and ev.ts - recent[0] > 60:
            recent.popleft()
        rate = float(len(recent))
        if ev.session_id:
            self.sessions[iid].add(ev.session_id)

        indicators: list[tuple[float, str]] = []
        signal = "identity_anomaly"
        allowed = True

        if boundary is None:
            indicators.append((0.6, "unknown identity (no registered permission boundary)"))
            signal, allowed = "boundary_violation", False
        else:
            ok, why = boundary.permits(ev.action, ev.resource)
            if not ok and (ev.action, ev.resource) not in self._exceptions[iid]:
                indicators.append((0.6, why))
                signal, allowed = "boundary_violation", False
            if not boundary.network_ok(ev.source_ip):
                indicators.append((0.35, f"source {ev.source_ip} outside allowed networks"))
            if not boundary.hour_ok(hour):
                indicators.append((0.15, f"activity at {hour:02d}:00 UTC outside allowed hours"))
            if boundary.max_rate_per_min and rate > boundary.max_rate_per_min:
                indicators.append((0.3, f"rate {rate:.0f}/min exceeds limit {boundary.max_rate_per_min}"))

        if not ev.success:
            fails = self._failures[iid]
            fails.append(ev.ts)
            while fails and ev.ts - fails[0] > cfg.failure_window_s:
                fails.popleft()
            if len(fails) >= cfg.failure_burst:
                indicators.append((0.5, f"{len(fails)} failed attempts in {cfg.failure_window_s:.0f}s"))
                signal = "credential_misuse"

        prof = self.profiles[iid]
        if prof.events >= cfg.learn_min_events:
            if ev.action not in prof.actions:
                indicators.append((0.15, f"first use of action {ev.action}"))
            if _resource_prefix(ev.resource) not in prof.resources:
                indicators.append((0.1, f"first access to {_resource_prefix(ev.resource)}"))
            if prof.hours[hour] / prof.events < 0.02:
                indicators.append((0.1, f"unusual hour {hour:02d}:00 UTC for this identity"))
            nk = _net_key(ev.source_ip)
            if nk not in prof.networks:
                indicators.append((0.2, f"new source network {nk}"))
            if prof.rate_ewma > 0 and rate > 5 * max(prof.rate_ewma, 1.0):
                indicators.append((0.2, f"request rate {rate:.0f}/min is >5x the usual {prof.rate_ewma:.1f}"))

        if indicators and any(fnmatch.fnmatch(ev.action, p) for p in SENSITIVE_ACTIONS):
            indicators.append((0.15, f"{ev.action} is a privilege-sensitive action"))

        p_benign = 1.0
        for w, _ in indicators:
            p_benign *= (1 - w)
        risk = round(1 - p_benign, 3)
        reasons = [r for _, r in indicators]

        if allowed and risk < cfg.anomaly_report_risk and ev.success:
            prof.learn(ev, hour, rate)

        finding = None
        if signal in ("boundary_violation", "credential_misuse") or risk >= cfg.anomaly_report_risk:
            sev = Severity.HIGH if risk >= cfg.high_risk else Severity.MEDIUM
            if signal == "identity_anomaly":
                an = self._anomalies[iid]
                an.append(ev.ts)
                while an and ev.ts - an[0] > cfg.anomaly_window_s:
                    an.popleft()
                if risk < cfg.high_risk:
                    sev = Severity.MEDIUM if len(an) >= cfg.anomaly_accumulation else Severity.LOW
                    if len(an) >= cfg.anomaly_accumulation:
                        reasons.append(f"{len(an)} anomalous events within {cfg.anomaly_window_s / 60:.0f} min")
            finding = Finding(
                detector=self.name, category=Category.IDENTITY, severity=sev,
                confidence=max(0.5, min(0.97, risk + 0.1)), asset_id=f"identity:{iid}",
                title=f"{signal.replace('_', ' ')}: {iid} {ev.action} {ev.resource}",
                description="; ".join(reasons), created_at=ev.ts, signal=signal,
                tags={"identity": iid, "key": iid},
                evidence=[Evidence("access", self.name, {
                    "identity": iid, "action": ev.action, "resource": ev.resource, "source_ip": ev.source_ip,
                    "success": ev.success, "risk": risk, "indicators": reasons, "allowed": allowed}, ev.ts)])
            self.stats["findings"] += 1
        self.stats["allowed" if allowed else "denied_boundary"] += 1
        return AccessDecision(allowed, risk, reasons, finding)

    # -- enforcement (called by the action dispatcher) -------------------------
    def freeze(self, identity_id: str, reason: str, now: float, by: str = "L3") -> dict[str, Any]:
        with self._lock:
            self.frozen[identity_id] = {"reason": reason, "at": now, "by": by}
            self.stats["freezes"] += 1
            return {"identity": identity_id, "frozen": True}

    def unfreeze(self, identity_id: str) -> bool:
        with self._lock:
            return self.frozen.pop(identity_id, None) is not None

    def revoke_sessions(self, identity_id: str) -> int:
        with self._lock:
            s = self.sessions.pop(identity_id, set())
            self.revoked_sessions |= s
            return len(s)

    # -- appeals ---------------------------------------------------------------
    def submit_appeal(self, identity_id: str, submitted_by: str, reason: str, now: float) -> Appeal:
        if identity_id not in self.frozen:
            raise ValueError(f"{identity_id} is not frozen")
        a = Appeal(identity_id, submitted_by, reason, now)
        self.appeals[a.id] = a
        return a

    def review_appeal(self, appeal_id: str, reviewer: str, grant: bool, now: float, note: str = "",
                      allow_rule: PermissionRule | None = None) -> Appeal:
        a = self.appeals[appeal_id]
        if a.status != AppealStatus.PENDING:
            raise ValueError(f"appeal {appeal_id} already {a.status.value}")
        if reviewer == a.submitted_by:
            raise ValueError("an appeal must be reviewed by someone other than the submitter")
        a.reviewer, a.reviewed_at, a.note = reviewer, now, note
        if grant:
            a.status = AppealStatus.GRANTED
            self.unfreeze(a.identity_id)
            self._failures.pop(a.identity_id, None)
            self._anomalies.pop(a.identity_id, None)
            if allow_rule:
                self.boundaries.setdefault(a.identity_id, PermissionBoundary()).allow.append(allow_rule)
            if self.on_false_positive:
                self.on_false_positive(a.identity_id)
        else:
            a.status = AppealStatus.DENIED
        return a

    def snapshot(self) -> dict[str, Any]:
        return {"identities": len(self.identities), "frozen": dict(self.frozen),
                "appeals": {k: v.status.value for k, v in self.appeals.items()}, "stats": dict(self.stats)}
