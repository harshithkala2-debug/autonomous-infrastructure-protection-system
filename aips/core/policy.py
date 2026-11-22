"""Authorisation policy: which level may do what, and when a human must approve.

This module answers the open design question "which actions each bot is
authorised to perform". Every action passes through ``AuthorizationPolicy``
before an executor touches infrastructure. The policy can:

* DENY an action outright (unknown kind, requester below the minimum level),
* REQUIRE_APPROVAL (high risk, protected target, critical asset, rate limit
  hit, kill switch engaged, autonomy ceiling exceeded), or
* ALLOW it.

High-risk approvals can require two distinct approvers (two-person rule).
"""

from __future__ import annotations

import fnmatch
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .clock import Clock, SystemClock
from .models import ActionRequest, Level, Risk, new_id


class Outcome(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class ActionSpec:
    kind: str
    risk: Risk
    reversible: bool
    min_level: Level
    always_approve: bool = False
    rate_per_hour: int = 6          # per (kind, target)
    description: str = ""


DEFAULT_CATALOG: dict[str, ActionSpec] = {s.kind: s for s in [
    ActionSpec("notify.humans", Risk.NONE, True, Level.L1_DETECTION, rate_per_hour=60,
               description="Page / message the on-call humans"),
    ActionSpec("service.restart", Risk.LOW, True, Level.L2_EVALUATION,
               description="Restart a service process or container"),
    ActionSpec("service.scale_out", Risk.LOW, True, Level.L2_EVALUATION,
               description="Add replicas / capacity to a service"),
    ActionSpec("storage.cleanup", Risk.LOW, False, Level.L2_EVALUATION,
               description="Remove rotated logs / temp files under allow-listed paths"),
    ActionSpec("storage.expand", Risk.MEDIUM, True, Level.L3_DECISION,
               description="Grow a volume"),
    ActionSpec("config.restore_baseline", Risk.MEDIUM, True, Level.L3_DECISION,
               description="Revert configuration to the recorded known-good state"),
    ActionSpec("traffic.throttle", Risk.LOW, True, Level.L2_EVALUATION, rate_per_hour=30,
               description="Close a valve partially (rate limit)"),
    ActionSpec("traffic.restrict", Risk.MEDIUM, True, Level.L3_DECISION, rate_per_hour=30,
               description="Admit only critical traffic through a valve"),
    ActionSpec("traffic.release", Risk.LOW, True, Level.L2_EVALUATION, rate_per_hour=60,
               description="Ramp a valve back open"),
    ActionSpec("host.isolate", Risk.HIGH, True, Level.L3_DECISION,
               description="Quarantine a host from the network"),
    ActionSpec("identity.freeze", Risk.MEDIUM, True, Level.L3_DECISION,
               description="Suspend an identity's access"),
    ActionSpec("identity.revoke_sessions", Risk.MEDIUM, False, Level.L3_DECISION,
               description="Invalidate active sessions / tokens"),
    ActionSpec("identity.unfreeze", Risk.LOW, True, Level.HUMAN,
               description="Restore access (appeal outcome)"),
    ActionSpec("backup.hold_replication", Risk.LOW, True, Level.L2_EVALUATION,
               description="Stop copying to the vault so corrupted data is not propagated"),
    ActionSpec("backup.restore", Risk.HIGH, False, Level.L3_DECISION, always_approve=True,
               description="Restore data from a verified snapshot"),
    ActionSpec("package.upgrade", Risk.HIGH, True, Level.L3_DECISION, always_approve=True,
               description="Upgrade a vulnerable software component"),
    ActionSpec("network.block_port", Risk.MEDIUM, True, Level.L3_DECISION,
               description="Block an exposed port at the host/network firewall"),
    ActionSpec("cert.renew", Risk.LOW, True, Level.L2_EVALUATION,
               description="Renew an expiring certificate"),
]}


@dataclass
class PolicyDecision:
    outcome: Outcome
    reason: str
    approvals_required: int = 0


@dataclass
class PolicyConfig:
    max_autonomous_risk: Risk = Risk.MEDIUM
    critical_asset_threshold: int = 5           # criticality >= this needs approval for risk >= MEDIUM
    protected_targets: list[str] = field(default_factory=lambda: ["break-glass-*"])
    global_actions_per_hour: int = 200
    two_person_rule_for_high: bool = True
    dry_run: bool = False

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyConfig":
        cfg = cls()
        if "max_autonomous_risk" in d:
            cfg.max_autonomous_risk = Risk[str(d["max_autonomous_risk"]).upper()]
        for k in ("critical_asset_threshold", "global_actions_per_hour"):
            if k in d:
                setattr(cfg, k, int(d[k]))
        if "protected_targets" in d:
            cfg.protected_targets = list(d["protected_targets"])
        for k in ("two_person_rule_for_high", "dry_run"):
            if k in d:
                setattr(cfg, k, bool(d[k]))
        return cfg


class AuthorizationPolicy:
    def __init__(self, config: PolicyConfig | None = None, catalog: dict[str, ActionSpec] | None = None,
                 clock: Clock | None = None):
        self.config = config or PolicyConfig()
        self.catalog = dict(catalog or DEFAULT_CATALOG)
        self.clock = clock or SystemClock()
        self.kill_switch = False
        self._history: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._global: deque[float] = deque()
        self._lock = threading.Lock()

    def spec(self, kind: str) -> ActionSpec | None:
        return self.catalog.get(kind)

    def _prune(self, dq: deque[float], now: float) -> None:
        while dq and now - dq[0] > 3600:
            dq.popleft()

    def evaluate(self, req: ActionRequest, asset_criticality: int = 3) -> PolicyDecision:
        spec = self.catalog.get(req.kind)
        if spec is None:
            return PolicyDecision(Outcome.DENY, f"unknown action kind '{req.kind}'")
        req.risk = max(req.risk, spec.risk)
        req.reversible = req.reversible and spec.reversible
        if req.requested_by < spec.min_level:
            return PolicyDecision(Outcome.DENY,
                                  f"{req.requested_by.name} may not request {req.kind} (min {spec.min_level.name})")
        approvals = 2 if (req.risk >= Risk.HIGH and self.config.two_person_rule_for_high) else 1
        if req.requested_by == Level.HUMAN:
            return PolicyDecision(Outcome.ALLOW, "human-initiated")
        if self.kill_switch and req.kind != "notify.humans":
            return PolicyDecision(Outcome.REQUIRE_APPROVAL, "kill switch engaged: autonomy suspended", approvals)
        if any(fnmatch.fnmatch(req.target, pat) for pat in self.config.protected_targets):
            return PolicyDecision(Outcome.REQUIRE_APPROVAL, f"target '{req.target}' is protected", approvals)
        if spec.always_approve:
            return PolicyDecision(Outcome.REQUIRE_APPROVAL, f"{req.kind} always requires approval", approvals)
        if req.risk > self.config.max_autonomous_risk:
            return PolicyDecision(Outcome.REQUIRE_APPROVAL,
                                  f"risk {req.risk.name} exceeds autonomy ceiling {self.config.max_autonomous_risk.name}",
                                  approvals)
        if asset_criticality >= self.config.critical_asset_threshold and req.risk >= Risk.MEDIUM:
            return PolicyDecision(Outcome.REQUIRE_APPROVAL,
                                  f"asset criticality {asset_criticality} requires approval for {req.risk.name} risk",
                                  approvals)
        now = self.clock.now()
        with self._lock:
            hist = self._history[(req.kind, req.target)]
            self._prune(hist, now)
            self._prune(self._global, now)
            if len(hist) >= spec.rate_per_hour:
                return PolicyDecision(Outcome.REQUIRE_APPROVAL,
                                      f"rate limit: {req.kind} on {req.target} ran {len(hist)}x in the last hour "
                                      "(repair-loop protection)", approvals)
            if len(self._global) >= self.config.global_actions_per_hour:
                return PolicyDecision(Outcome.REQUIRE_APPROVAL, "global autonomous action budget exhausted", approvals)
        return PolicyDecision(Outcome.ALLOW, "within autonomous policy")

    def record_execution(self, req: ActionRequest) -> None:
        now = self.clock.now()
        with self._lock:
            self._history[(req.kind, req.target)].append(now)
            self._global.append(now)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class Approval:
    request: ActionRequest
    reason: str
    created_at: float
    approvals_required: int = 1
    approvers: list[str] = field(default_factory=list)
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_at: float | None = None
    note: str = ""
    ttl_seconds: float = 4 * 3600
    id: str = field(default_factory=lambda: new_id("APR"))


class ApprovalQueue:
    def __init__(self, clock: Clock | None = None):
        self.clock = clock or SystemClock()
        self._items: dict[str, Approval] = {}
        self._lock = threading.Lock()

    def submit(self, req: ActionRequest, reason: str, approvals_required: int = 1) -> Approval:
        with self._lock:
            for a in self._items.values():
                if (a.status == ApprovalStatus.PENDING and a.request.kind == req.kind
                        and a.request.target == req.target and a.request.incident_id == req.incident_id):
                    return a
            ap = Approval(req, reason, self.clock.now(), approvals_required)
            self._items[ap.id] = ap
            return ap

    def get(self, approval_id: str) -> Approval | None:
        return self._items.get(approval_id)

    def pending(self) -> list[Approval]:
        self.expire()
        return [a for a in self._items.values() if a.status == ApprovalStatus.PENDING]

    def all(self) -> list[Approval]:
        return list(self._items.values())

    def expire(self) -> list[Approval]:
        now = self.clock.now()
        out = []
        with self._lock:
            for a in self._items.values():
                if a.status == ApprovalStatus.PENDING and now - a.created_at > a.ttl_seconds:
                    a.status, a.decided_at, a.note = ApprovalStatus.EXPIRED, now, "expired without decision"
                    out.append(a)
        return out

    def approve(self, approval_id: str, approver: str, note: str = "") -> Approval:
        with self._lock:
            a = self._items[approval_id]
            if a.status != ApprovalStatus.PENDING:
                raise ValueError(f"approval {approval_id} is {a.status.value}")
            if approver in a.approvers:
                raise ValueError(f"{approver} already approved {approval_id}; a distinct approver is required")
            a.approvers.append(approver)
            if note:
                a.note = note
            if len(a.approvers) >= a.approvals_required:
                a.status, a.decided_at = ApprovalStatus.APPROVED, self.clock.now()
            return a

    def reject(self, approval_id: str, approver: str, note: str = "") -> Approval:
        with self._lock:
            a = self._items[approval_id]
            if a.status != ApprovalStatus.PENDING:
                raise ValueError(f"approval {approval_id} is {a.status.value}")
            a.status, a.decided_at, a.note = ApprovalStatus.REJECTED, self.clock.now(), note
            a.approvers.append(approver)
            return a
