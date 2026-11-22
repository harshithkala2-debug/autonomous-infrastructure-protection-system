"""The AIPS orchestrator: wires every fleet together and runs the control loop.

One ``tick`` is one end-to-end pass of the concept's workflow (section 8):

1. telemetry is collected from every source;
2. Level 1 detectors (plus the identity, backup and intel fleets) emit findings;
3. each finding is routed: standard path to Level 2, or bypass to Level 3;
4. Level 2 evaluates cases and dismisses, monitors, handles or escalates;
5. Level 3 opens/updates incidents, selects playbooks, resolves conflicts and
   acts through the authorisation policy and action dispatcher;
6. active incidents are verified, retried, resolved or failed;
7. valves ramp back open where the protected component is healthy again;
8. outcomes feed the learning memory and the tamper-evident audit ledger.
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from .backup.manager import BackupManager
from .core.audit import AuditLedger
from .core.bus import EventBus
from .core.clock import Clock, SystemClock
from .core.models import (ActionRequest, Disposition, Finding, IncidentStatus, Level, Verdict, to_jsonable)
from .core.policy import ApprovalQueue, AuthorizationPolicy, PolicyConfig
from .decision.engine import DecisionEngine
from .core.mesh import LayerMesh
from .decision.playbooks import PlaybookLibrary, signal_rank
from .decision.strategies import StrategySelector
from .experience.store import ExperienceStore
from .decision.verification import Verifier
from .evaluation.escalation import EscalationConfig, EscalationRouter
from .evaluation.evaluator import EvaluatorConfig, Level2Evaluator
from .evaluation.learning import OutcomeMemory
from .identity.guard import AccessDecision, AccessEvent, IdentityGuard, PermissionRule
from .intel.models import Advisory, IncidentReport
from .intel.patterns import EnvContext
from .intel.relevance import RelevanceEngine
from .monitoring.detectors import Level1Fleet, ThresholdRule, default_fleet, inspect_asset
from .repair.baseline import DesiredStateStore
from .repair.executor import ActionDispatcher, InfrastructureAdapter, Notifier
from .telemetry.inventory import Inventory
from .telemetry.sources import Observation, TelemetrySource
from .traffic.valves import TrafficController, ValveConfig

log = logging.getLogger("aips")


@dataclass
class AIPSConfig:
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    escalation: EscalationConfig = field(default_factory=EscalationConfig)
    evaluator: EvaluatorConfig = field(default_factory=EvaluatorConfig)
    valves: ValveConfig = field(default_factory=ValveConfig)
    thresholds: list[ThresholdRule] | None = None
    backup_replicate_every_tick: bool = True
    strategy_exploration: bool = True
    strategy_seed: int = 0


@dataclass
class TickReport:
    tick: int
    ts: float
    findings: int
    routed_l2: int
    routed_l3: int
    verdicts: dict[str, int]
    active_incidents: int
    new_incidents: list[str]


def _case_key(f: Finding) -> str:
    return f"{f.asset_id}|{f.category.value}|{f.signal}"


class AIPS:
    def __init__(self, inventory: Inventory, adapter: InfrastructureAdapter,
                 sources: Iterable[TelemetrySource] = (), *, clock: Clock | None = None,
                 config: AIPSConfig | None = None, audit: AuditLedger | None = None,
                 baselines: DesiredStateStore | None = None, memory: OutcomeMemory | None = None,
                 backup: BackupManager | None = None, guard: IdentityGuard | None = None,
                 notifier: Notifier | None = None, playbooks: PlaybookLibrary | None = None,
                 fleet: Level1Fleet | None = None, experience: ExperienceStore | None = None):
        self.clock = clock or SystemClock()
        self.config = config or AIPSConfig()
        self.inventory = inventory
        self.adapter = adapter
        self.sources = list(sources)
        self.bus = EventBus()
        self.audit = audit or AuditLedger(clock=self.clock)
        self.baselines = baselines or DesiredStateStore()
        self.run_id = uuid.uuid4().hex[:10]
        self.experience = experience or ExperienceStore(":memory:")
        self.experience.run_id = self.experience.run_id or self.run_id
        # the experience store doubles as persistent detector-outcome memory unless one is supplied explicitly
        self.memory = memory or self.experience
        self.mesh = LayerMesh(self.audit)
        self.backup = backup
        self.notifier = notifier or Notifier()
        self.playbooks = playbooks or PlaybookLibrary()
        self.policy = AuthorizationPolicy(self.config.policy, clock=self.clock)
        self.approvals = ApprovalQueue(self.clock)
        self.router = EscalationRouter(self.config.escalation)
        self.evaluator = Level2Evaluator(inventory, self.memory, self.config.evaluator, self.playbooks.l2_signals())
        self.fleet = fleet or default_fleet(self.baselines, self.config.thresholds)
        self.guard = guard or IdentityGuard()
        self.guard.on_false_positive = self._identity_false_positive
        self.traffic = TrafficController(self.config.valves, on_change=self._valve_changed)
        self.relevance = RelevanceEngine(inventory)
        self.dispatcher = ActionDispatcher(adapter, self.clock.now, dry_run=self.config.policy.dry_run)
        self._register_handlers()
        self.verifier = Verifier(self.baselines, self.guard.is_frozen, adapter.health)
        self.selector = StrategySelector(self.experience, self.config.strategy_seed,
                                         enabled=self.config.strategy_exploration)
        self.engine = DecisionEngine(self.policy, self.approvals, self.dispatcher, self.playbooks, inventory,
                                     self.verifier, self.audit, self.bus, self.clock, self.memory,
                                     selector=self.selector, experience=self.experience, mesh=self.mesh)
        self.evaluator.under_mitigation = self._under_mitigation
        self.evaluator.mesh = self.mesh
        self._register_capabilities()
        self._pending: list[Finding] = []
        self._last_disposition: dict[str, Disposition] = {}
        self.last_obs: Observation | None = None
        self.ticks = 0
        self.counters: Counter = Counter()
        self.verdict_log: list[Verdict] = []
        self.audit.append("system", "aips.started", {"assets": len(inventory), "sources": [s.name for s in self.sources],
                                                     "adapter": adapter.name, "dry_run": self.config.policy.dry_run})

    # ------------------------------------------------------------------ layer mesh
    def _register_capabilities(self) -> None:
        m = self.mesh

        def rescan(p: dict[str, Any]) -> dict[str, Any]:
            asset = p["asset"]
            now = self.clock.now()
            obs = self.collect(now)
            found = inspect_asset(obs, asset, self.inventory, self.baselines, self.config.thresholds, now)
            return {"asset": asset, "keys": sorted({_case_key(f) for f in found}),
                    "findings": [{"key": _case_key(f), "signal": f.signal, "severity": f.severity.name,
                                  "confidence": f.confidence, "title": f.title} for f in found]}

        def escalate(p: dict[str, Any]) -> str | None:
            inc = self.engine.submit(Level.L3_DECISION, list(p["findings"]), p.get("reason", "direct escalation"),
                                     p.get("verdict"))
            return inc.id if inc else None

        def incidents(p: dict[str, Any]) -> list[dict[str, Any]]:
            return [{"id": i.id, "signal": i.signal, "status": i.status.value, "strategy": i.playbook}
                    for i in self.engine.incidents.values() if i.asset_id == p.get("asset", i.asset_id)]

        def case(p: dict[str, Any]) -> list[dict[str, Any]]:
            return [{"key": c.key, "occurrences": c.occurrences, "max": c.max_disposition.value}
                    for c in self.evaluator.cases.values() if c.asset_id == p["asset"]
                    and (not p.get("signal") or c.signal == p["signal"])]

        m.register("L1", "rescan", rescan, "fresh, side-effect-free detection pass on one asset")
        m.register("L1", "probe", lambda p: {"up": self.adapter.health(p["asset"])}, "adapter health probe")
        m.register("L2", "case", case, "Level 2's current view of an asset's cases")
        m.register("L3", "escalate", escalate, "open or update a Level 3 incident directly")
        m.register("L3", "incidents", incidents, "incidents for an asset")
        m.register("experience", "recurrence",
                   lambda p: self.experience.recurrence(p["asset"], p["signal"], float(p.get("since", 0))),
                   "how many incidents this asset+signal had since a time")
        m.register("experience", "similar",
                   lambda p: self.experience.similar(p["signal"], p.get("asset"), int(p.get("limit", 5))),
                   "most relevant past episodes")
        m.register("experience", "strategy_stats",
                   lambda p: self.experience.strategy_stats(p["signal"], p.get("asset")),
                   "per-strategy track record for a signal")
        m.register("experience", "summary", lambda p: self.experience.summary(), "what AIPS has lived through")
        m.register("identity", "status", lambda p: {"frozen": self.guard.is_frozen(p["identity"]),
                                                    "events_learned": self.guard.profiles[p["identity"]].events},
                   "identity freeze / profile state")
        m.register("traffic", "state", lambda p: [v for v in self.traffic.snapshot() if v["asset"] == p["asset"]],
                   "valve positions for an asset")
        if self.backup is not None:
            m.register("backup", "status", lambda p: self.backup.status(), "backup layers and replication state")

    # ------------------------------------------------------------------ wiring
    def _under_mitigation(self, asset_id: str) -> bool:
        """True while AIPS itself is changing this asset (or just finished): deviations are expected."""
        now = self.clock.now()
        for inc in self.engine.incidents.values():
            if inc.asset_id != asset_id:
                continue
            if inc.active or (inc.resolved_at is not None and now - inc.resolved_at < 600):
                return True
        return any(v.asset_id == asset_id and (v.position < 1.0 or v.ramping) for v in self.traffic.valves())

    def _valve_changed(self, asset_id: str, kind: str, position: float) -> None:
        hook = getattr(self.adapter, "apply_valve", None)
        if hook:
            hook(asset_id, kind, position)
        self.bus.publish("valve.changed", {"asset": asset_id, "valve": kind, "position": position})

    def _register_handlers(self) -> None:
        d = self.dispatcher
        now = self.clock.now

        def traffic(req: ActionRequest):
            kind = req.params.get("valve", "both")
            if req.kind == "traffic.throttle":
                prev = self.traffic.position(req.target, "ingress" if kind == "both" else kind)
                v = self.traffic.throttle(req.target, kind, float(req.params.get("position", 0.5)),
                                          req.rationale or "throttle", now(), autonomous=req.requested_by < Level.HUMAN)
                return True, f"{kind} valve -> {v.position:.2f} ({v.mode.value})", {"previous": prev, "valve": kind}
            if req.kind == "traffic.restrict":
                self.traffic.restrict(req.target, req.rationale or "restrict", now())
                return True, "both valves restricted to critical traffic", None
            if req.kind == "traffic.release":
                self.traffic.release(req.target, req.rationale or "release", now(), kind)
                return True, f"{kind} valve(s) ramping open", None
            return False, f"unknown traffic action {req.kind}", None

        def identity(req: ActionRequest):
            if req.kind == "identity.freeze":
                self.guard.freeze(req.target, req.rationale, now(), by=req.requested_by.name)
                detail = f"{req.target} frozen in AIPS"
                hook = getattr(self.adapter, "freeze_identity", None)
                if hook:                                   # enforce on the platform too (e.g. disable a GCP SA)
                    ok, msg = hook(req.target, True)
                    detail += f"; platform: {msg}"
                return True, detail, {"identity": req.target}
            if req.kind == "identity.revoke_sessions":
                n = self.guard.revoke_sessions(req.target)
                return True, f"{n} session(s) revoked", None
            if req.kind == "identity.unfreeze":
                was_frozen = self.guard.unfreeze(req.target)
                hook = getattr(self.adapter, "freeze_identity", None)
                if hook:                                   # always restore on the platform as well
                    p_ok, msg = hook(req.target, False)
                    return was_frozen or p_ok, f"unfrozen; platform: {msg}", None
                return was_frozen, "unfrozen" if was_frozen else "identity was not frozen", None
            return False, f"unknown identity action {req.kind}", None

        def backup(req: ActionRequest):
            if self.backup is None:
                return False, "no backup manager configured", None
            if req.kind == "backup.hold_replication":
                self.backup.hold_replication(req.rationale or "held by incident response")
                return True, "vault replication held", None
            if req.kind == "backup.restore":
                rep = self.backup.restore(str(req.params.get("snapshot", "latest_clean")), clean_target=True)
                return rep.verified, f"restored {rep.files} files from {rep.snapshot_id}; verified={rep.verified}", None
            return False, f"unknown backup action {req.kind}", None

        def notify(req: ActionRequest):
            ok = self.notifier.send(f"AIPS {req.params.get('severity', 'INFO')}: {req.target}",
                                    str(req.params.get("message", "")), str(req.params.get("severity", "info")),
                                    {"incident": req.incident_id})
            return ok, "notified", None

        def identity_rollback(res):
            if res.kind == "identity.freeze":
                hook = getattr(self.adapter, "freeze_identity", None)
                if hook:
                    hook(res.target, False)
                return self.guard.unfreeze(res.target), "unfrozen by rollback"
            return False, "no rollback"

        d.register("traffic.", traffic)
        d.register("identity.", identity)
        d.register("backup.", backup)
        d.register("notify.", notify)
        d.rollback_handlers["identity."] = identity_rollback

    # ------------------------------------------------------------------ inputs
    def ingest_access(self, event: AccessEvent) -> AccessDecision:
        dec = self.guard.evaluate(event)
        if dec.finding:
            self._pending.append(dec.finding)
        if not dec.allowed:
            self.counters["access_denied"] += 1
        return dec

    def ingest_findings(self, findings: Iterable[Finding]) -> None:
        self._pending.extend(findings)

    def run_intel(self, advisories: list[Advisory] = (), reports: list[IncidentReport] = ()) -> dict[str, Any]:
        now = self.clock.now()
        rep_a = self.relevance.assess_advisories(list(advisories), now)
        ctx = EnvContext(self.inventory, now, self.backup.status() if self.backup else None,
                         self.guard.boundaries)
        rep_r = self.relevance.assess_reports(list(reports), ctx)
        self._pending.extend(rep_a.findings + rep_r.findings)
        summary = {
            "advisories_checked": rep_a.advisories_checked, "reports_checked": rep_r.reports_checked,
            "confirmed": sum(1 for m in rep_a.matches if m.status == "confirmed"),
            "possible": sum(1 for m in rep_a.matches if m.status == "possible"),
            "not_affected": sum(1 for m in rep_a.matches if m.status == "not_affected"),
            "pattern_findings": len(rep_r.findings), "findings": len(rep_a.findings) + len(rep_r.findings),
        }
        self.audit.append("intel", "intel.assessed", summary)
        return summary

    # ------------------------------------------------------------------ loop
    def collect(self, now: float) -> Observation:
        obs = Observation(ts=now)
        for s in self.sources:
            try:
                obs.merge(s.collect(now))
            except Exception as exc:  # noqa: BLE001 - one broken source must not stop the loop
                self.counters["source_errors"] += 1
                log.error("telemetry source %s failed: %s", s.name, exc)
        return obs

    def tick(self) -> TickReport:
        self.ticks += 1
        now = self.clock.now()
        if self.backup and self.backup.due(now):
            try:
                self.backup.snapshot(now)
                if self.config.backup_replicate_every_tick:
                    self.backup.replicate(now)
            except Exception as exc:  # noqa: BLE001
                self.counters["backup_errors"] += 1
                log.error("backup cycle failed: %s", exc)
        obs = self.collect(now)
        self.last_obs = obs
        # access events from telemetry (e.g. cloud audit logs) go to the identity guard
        for ev in [e for e in obs.events if e.get("type") == "access"]:
            try:
                self.ingest_access(AccessEvent(ev["identity"], ev["action"], ev.get("resource", ""),
                                               float(ev.get("ts", now)), ev.get("source_ip"),
                                               bool(ev.get("success", True)), ev.get("session")))
            except (KeyError, TypeError, ValueError):
                self.counters["bad_access_events"] += 1
        findings = self.fleet.run(obs, self.inventory, self.baselines, now)
        if self.backup:
            findings += self.backup.drain_findings()
        findings += self._pending
        self._pending = []
        for f in findings:
            if not f.route:
                f.route.append(1)
            self.bus.publish("finding.l1", f)
        self.counters["findings"] += len(findings)
        self.evaluator.observe_context(findings, now)
        current_keys = {_case_key(f) for f in findings}

        before = set(self.engine.incidents)
        l2: list[Finding] = []
        n3 = 0
        known = set(self.inventory.ids())
        # upstream assets first, so a dependency's incident exists before its dependents' symptoms arrive;
        # within an asset, the most causal signal first, so it selects the playbook
        findings.sort(key=lambda f: (len(self.inventory.upstream_closure(f.asset_id)) if f.asset_id in known else 0,
                                     f.asset_id, signal_rank(f.signal)))
        for f in findings:
            level, reason = self.router.route(f)
            if level == Level.L3_DECISION:
                n3 += 1
                # the producing layer calls Level 3 directly through the mesh (bypass)
                caller = "L1" if f.detector.startswith("l1.") else f.detector.split(".")[0]
                self.mesh.call(caller, "L3", "escalate", {"findings": [f], "reason": reason})
            else:
                l2.append(f)
        verdicts = self.evaluator.evaluate(l2, now)
        vcount: Counter = Counter()
        for v in verdicts:
            vcount[v.disposition.value] += 1
            self.verdict_log.append(v)
            if self._last_disposition.get(v.case_key) != v.disposition:
                self._last_disposition[v.case_key] = v.disposition
                self.audit.append("L2", f"verdict.{v.disposition.value}",
                                  {"case": v.case_key, "severity": v.severity.name, "confidence": v.confidence,
                                   "rationale": v.rationale, "findings": [f.id for f in v.findings]})
                self.bus.publish(f"verdict.{v.disposition.value}", v)
            if v.disposition == Disposition.ESCALATE:
                self.engine.submit(Level.L3_DECISION, v.findings, "escalated by Level 2", v)
            elif v.disposition == Disposition.HANDLE:
                self.engine.submit(Level.L2_EVALUATION, v.findings, "handled at Level 2", v)
            elif v.disposition == Disposition.DISMISS and v.severity.name == "INFO":
                self._last_disposition.pop(v.case_key, None)     # expired case: allow a fresh audit entry later
        self.verdict_log = self.verdict_log[-5000:]

        self.engine.tick(obs, current_keys)
        self.traffic.tick(now, lambda a: not _case_key_asset(current_keys, a))
        new = [i for i in self.engine.incidents if i not in before]
        return TickReport(self.ticks, now, len(findings), len(l2), n3, dict(vcount),
                          len(self.engine.active()), new)

    # ------------------------------------------------------------------ human operations
    def approve(self, approval_id: str, approver: str, note: str = "") -> dict[str, Any]:
        ap = self.approvals.approve(approval_id, approver, note)
        self.audit.append(approver, "approval.approve", {"approval": approval_id, "status": ap.status.value,
                                                         "approvers": ap.approvers, "note": note})
        return {"id": ap.id, "status": ap.status.value, "approvers": ap.approvers,
                "required": ap.approvals_required}

    def reject(self, approval_id: str, approver: str, note: str = "") -> dict[str, Any]:
        ap = self.approvals.reject(approval_id, approver, note)
        self.audit.append(approver, "approval.reject", {"approval": approval_id, "note": note})
        return {"id": ap.id, "status": ap.status.value}

    def set_kill_switch(self, engaged: bool, by: str, reason: str = "") -> None:
        self.policy.kill_switch = engaged
        self.audit.append(by, "killswitch." + ("engaged" if engaged else "released"), {"reason": reason})
        self.notifier.send("AIPS kill switch " + ("ENGAGED" if engaged else "released"), reason or by, "high")

    def capture_baseline(self, asset_id: str, approved_by: str) -> dict[str, Any]:
        obs = self.last_obs or self.collect(self.clock.now())
        cfg = obs.configs.get(asset_id)
        if cfg is None:
            raise KeyError(f"no configuration observed for {asset_id}")
        asset = self.inventory.get(asset_id)
        b = self.baselines.capture(asset_id, cfg, obs.open_ports.get(asset_id, []),
                                   {s.name: s.version for s in asset.software} if asset else {},
                                   self.clock.now(), approved_by)
        self.audit.append(approved_by, "baseline.captured", {"asset": asset_id, "version": b.version})
        return {"asset": asset_id, "version": b.version}

    def submit_appeal(self, identity_id: str, submitted_by: str, reason: str) -> dict[str, Any]:
        a = self.guard.submit_appeal(identity_id, submitted_by, reason, self.clock.now())
        self.audit.append(submitted_by, "appeal.submitted", {"appeal": a.id, "identity": identity_id, "reason": reason})
        self.notifier.send(f"Appeal {a.id} for {identity_id}", reason, "medium")
        return {"id": a.id, "status": a.status.value}

    def review_appeal(self, appeal_id: str, reviewer: str, grant: bool, note: str = "",
                      allow_action: str | None = None, allow_resource: str = "*") -> dict[str, Any]:
        rule = PermissionRule(allow_action, allow_resource) if allow_action else None
        a = self.guard.review_appeal(appeal_id, reviewer, grant, self.clock.now(), note, rule)
        platform = None
        if grant:
            # restore access everywhere the freeze was enforced (e.g. re-enable a cloud service account)
            res = self.dispatcher.execute(ActionRequest("identity.unfreeze", a.identity_id, {}, Level.HUMAN,
                                                        rationale=f"appeal {a.id} granted by {reviewer}"))
            platform = res.detail
        self.audit.append(reviewer, "appeal." + a.status.value,
                          {"appeal": a.id, "identity": a.identity_id, "note": note,
                           "boundary_amended": bool(rule), "restore": platform})
        return {"id": a.id, "status": a.status.value, "identity": a.identity_id,
                "frozen": self.guard.is_frozen(a.identity_id), "restore": platform}

    def _identity_false_positive(self, identity_id: str) -> None:
        for inc in list(self.engine.incidents.values()):
            if inc.asset_id == f"identity:{identity_id}" and inc.status in (IncidentStatus.RESOLVED,
                                                                            IncidentStatus.VERIFYING,
                                                                            IncidentStatus.MITIGATING):
                self.engine.close_human_incident(inc.id, "appeal-review", "access restored on appeal",
                                                 false_positive=True)

    # ------------------------------------------------------------------ views
    def status(self) -> dict[str, Any]:
        incs = list(self.engine.incidents.values())
        return {
            "ticks": self.ticks, "now": self.clock.now(), "kill_switch": self.policy.kill_switch,
            "dry_run": self.dispatcher.dry_run, "assets": len(self.inventory),
            "incidents": {s.value: sum(1 for i in incs if i.status == s) for s in IncidentStatus},
            "pending_approvals": len(self.approvals.pending()),
            "valves": [v for v in self.traffic.snapshot() if v["position"] < 1.0 or v["ramping"]],
            "identity": self.guard.snapshot(),
            "backup": self.backup.status() if self.backup else None,
            "audit": {"records": len(self.audit), "verified": self.audit.verify()[0]},
            "counters": dict(self.counters),
            "detectors": {k: vars(v) for k, v in self.fleet.stats.items()},
            "bus": self.bus.stats(),
            "mesh": self.mesh.snapshot(),
            "experience": {k: v for k, v in self.experience.summary().items() if k != "detectors"},
        }

    def incident_view(self, incident_id: str) -> dict[str, Any]:
        return to_jsonable(self.engine.incidents[incident_id])

    def metrics_text(self) -> str:
        st = self.status()
        lines = ["# HELP aips_incidents Incidents by status", "# TYPE aips_incidents gauge"]
        lines += [f'aips_incidents{{status="{k}"}} {v}' for k, v in st["incidents"].items()]
        lines += ["# TYPE aips_pending_approvals gauge", f"aips_pending_approvals {st['pending_approvals']}",
                  "# TYPE aips_findings_total counter", f"aips_findings_total {self.counters['findings']}",
                  "# TYPE aips_ticks_total counter", f"aips_ticks_total {self.ticks}",
                  "# TYPE aips_kill_switch gauge", f"aips_kill_switch {int(self.policy.kill_switch)}",
                  "# TYPE aips_valve_position gauge"]
        lines += [f'aips_valve_position{{asset="{v["asset"]}",valve="{v["kind"]}"}} {v["position"]}'
                  for v in self.traffic.snapshot()]
        lines += ["# TYPE aips_frozen_identities gauge", f"aips_frozen_identities {len(self.guard.frozen)}"]
        return "\n".join(lines) + "\n"


def _case_key_asset(keys: set[str], asset_id: str) -> bool:
    """True if a non-statistical finding exists for the asset in this cycle (valve ramp regression signal)."""
    return any(k.startswith(asset_id + "|") and "|anomaly:" not in k for k in keys)
