"""Incident lifecycle engine used by Level 2 (handling) and Level 3 (final decisions).

Lifecycle::

    OPEN -> MITIGATING -> (AWAITING_APPROVAL ->) VERIFYING -> RESOLVED
                 ^                                   |
                 +------ retry (attempt n+1) --------+--> FAILED (rollback, humans)

* Level 2 incidents run only Level-2-authorised steps. If a step needs more
  authority, or Level 2 exhausts its attempts, the incident is escalated to
  Level 3 rather than failed.
* An incident whose upstream dependency has an active availability incident
  is held as a *symptom*; when the root cause is resolved it is re-verified
  and only remediated itself if the symptom persists.
* Conflicts between incidents acting on the same target are resolved by
  playbook priority (containment > integrity > availability > performance);
  an isolated target receives no availability actions.
* Every transition is written to the audit ledger and published on the bus.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..core.audit import AuditLedger
from ..core.bus import EventBus
from ..core.clock import Clock
from ..core.models import (ActionRequest, ActionResult, Category, Finding, Incident, IncidentStatus, Level,
                           Severity, Verdict, to_jsonable)
from ..core.policy import ApprovalQueue, ApprovalStatus, AuthorizationPolicy, Outcome
from ..evaluation.learning import OutcomeMemory
from ..experience.store import Episode, reward_for
from ..repair.executor import ActionDispatcher
from ..telemetry.inventory import Inventory
from ..telemetry.sources import Observation
from .playbooks import Playbook, PlaybookLibrary
from .strategies import Choice, StrategySelector
from .verification import Verifier

CONTAINMENT_KINDS = {"host.isolate", "identity.freeze", "identity.revoke_sessions", "identity.revert_actions",
                     "network.block_port", "backup.hold_replication", "agent.freeze", "agent.revert_actions"}
AVAILABILITY_KINDS = {"service.restart", "service.scale_out", "traffic.release", "config.restore_baseline",
                      "storage.expand", "package.upgrade"}
EXCLUSIVE = {
    "identity.freeze": {"identity.unfreeze"},
    "identity.unfreeze": {"identity.freeze"},
    "agent.freeze": {"agent.unfreeze"},
    "agent.unfreeze": {"agent.freeze"},
    "backup.restore": {"service.restart", "config.restore_baseline", "package.upgrade"},
    "traffic.release": {"traffic.throttle", "traffic.restrict"},
}
ROOT_CAUSE_CATEGORIES = {Category.AVAILABILITY, Category.PERFORMANCE, Category.CAPACITY}
PRECHECK_CATEGORIES = ROOT_CAUSE_CATEGORIES | {Category.CONFIGURATION}
CHRONIC_WINDOW_S = 7 * 86400


@dataclass
class Runtime:
    playbook: Playbook | None
    trigger: Finding
    step: int = 0
    settle: int = 0
    waiting: str | None = None
    held_by: str | None = None
    verify_only: bool = False
    max_attempts: int = 3
    fingerprints: set[tuple[str, str]] = field(default_factory=set)
    keys: set[str] = field(default_factory=set)       # primary key + correlated symptom keys
    # strategy exploration / experience
    candidates: list[Playbook] = field(default_factory=list)
    tried: list[str] = field(default_factory=list)
    strategy_attempt: int = 1
    explored: bool = False
    episode_start: float = 0.0
    episode_action_idx: int = 0
    episode_seq: int = 0
    last_episode_id: str | None = None


class ConflictResolver:
    def __init__(self) -> None:
        self.containment: dict[str, str] = {}               # target -> incident id
        self.tick_claims: dict[str, list[tuple[int, str, str]]] = {}

    def new_tick(self) -> None:
        self.tick_claims = {}

    def check(self, req: ActionRequest, incident_id: str, priority: int) -> str | None:
        owner = self.containment.get(req.target)
        if owner and owner != incident_id and req.kind in AVAILABILITY_KINDS:
            return f"target {req.target} is contained by {owner}; containment takes priority"
        for prio, other, kind in self.tick_claims.get(req.target, []):
            if other != incident_id and kind in EXCLUSIVE.get(req.kind, set()) and prio <= priority:
                return f"conflicts with {kind} by {other} (priority {prio} <= {priority})"
        return None

    def claim(self, req: ActionRequest, incident_id: str, priority: int) -> None:
        self.tick_claims.setdefault(req.target, []).append((priority, incident_id, req.kind))
        if req.kind == "host.isolate":
            self.containment[req.target] = incident_id

    def release_containment(self, target: str) -> None:
        self.containment.pop(target, None)


class DecisionEngine:
    name = "l3.decision"

    def __init__(self, policy: AuthorizationPolicy, approvals: ApprovalQueue, dispatcher: ActionDispatcher,
                 playbooks: PlaybookLibrary, inventory: Inventory, verifier: Verifier, audit: AuditLedger,
                 bus: EventBus, clock: Clock, memory: OutcomeMemory, reopen_window_s: float = 900.0,
                 selector: StrategySelector | None = None, experience: Any = None, mesh: Any = None,
                 chronic_threshold: int = 3):
        self.policy, self.approvals, self.dispatcher = policy, approvals, dispatcher
        self.playbooks, self.inventory, self.verifier = playbooks, inventory, verifier
        self.audit, self.bus, self.clock, self.memory = audit, bus, clock, memory
        self.reopen_window = reopen_window_s
        self.selector = selector
        self.experience = experience
        self.mesh = mesh
        self.chronic_threshold = chronic_threshold
        self.incidents: dict[str, Incident] = {}
        self.runtime: dict[str, Runtime] = {}
        self.active_by_key: dict[str, str] = {}
        self.recent_resolved: dict[str, str] = {}
        self.failed_by_key: dict[str, str] = {}      # failed incidents stay with humans until closed
        self.conflicts = ConflictResolver()

    # ------------------------------------------------------------------ helpers
    def _actor(self, inc: Incident) -> str:
        return {Level.L2_EVALUATION: "L2", Level.L3_DECISION: "L3", Level.HUMAN: "human"}.get(inc.level, "L3")

    def _event(self, inc: Incident, event: str, detail: str = "", payload: dict | None = None) -> None:
        now = self.clock.now()
        inc.log(now, self._actor(inc), event, detail)
        self.audit.append(self._actor(inc), f"incident.{event}",
                          {"incident": inc.id, "asset": inc.asset_id, "signal": inc.signal,
                           "status": inc.status.value, "detail": detail, **(payload or {})})
        self.bus.publish(f"incident.{event}", inc)

    def render(self, value: Any, inc: Incident, trigger: Finding) -> Any:
        if isinstance(value, dict):
            return {k: self.render(v, inc, trigger) for k, v in value.items()}
        if isinstance(value, list):
            return [self.render(v, inc, trigger) for v in value]
        if not isinstance(value, str):
            return value
        ev = trigger.evidence[0].data if trigger.evidence else {}

        def sub(m: re.Match) -> str:
            token = m.group(1)
            if token == "asset":
                return inc.asset_id
            if token.startswith("tag:"):
                return str(trigger.tags.get(token[4:], ""))
            if token.startswith("evidence:"):
                return str(ev.get(token[9:], ""))
            return m.group(0)

        out = re.sub(r"\{([a-z]+(?::[A-Za-z0-9_]+)?)\}", sub, value)
        return int(out) if out.isdigit() and value != out else out

    def active(self) -> list[Incident]:
        return [i for i in self.incidents.values() if i.active]

    # ------------------------------------------------------------------ strategies & experience
    def _choose(self, inc: Incident, rt: Runtime, exclude: list[str] | None = None) -> Choice | None:
        cands = rt.candidates
        if not cands:
            return None
        if len(cands) == 1 and not exclude:
            return Choice(cands[0], False, "single")
        if self.selector is None:
            pool = [c for c in cands if c.name not in (exclude or [])]
            return Choice(pool[0], False, "fixed") if pool else None
        has_history = bool(self.experience and self.experience.strategy_stats(inc.signal, inc.asset_id))
        critical = self.inventory.criticality(inc.asset_id) >= 5
        if not exclude and (not has_history or critical):
            # cold start or business-critical asset: use the expert-reviewed canonical strategy
            return Choice(cands[0], False, "fixed" if critical else "canonical")
        return self.selector.choose(cands, inc.signal, inc.asset_id, exclude or [],
                                    mode="switch" if exclude else "thompson", now=self.clock.now())

    def _apply_choice(self, inc: Incident, rt: Runtime, choice: Choice, event: str) -> None:
        rt.playbook = choice.playbook
        rt.tried.append(choice.playbook.name)
        rt.strategy_attempt = 1
        rt.explored = choice.explored
        inc.playbook = choice.playbook.name
        if choice.mode not in ("single",):
            self._event(inc, event, choice.describe(),
                        {"strategy": choice.playbook.name, "explored": choice.explored, "mode": choice.mode})

    def _start_episode(self, inc: Incident, rt: Runtime) -> None:
        rt.episode_start = self.clock.now()
        rt.episode_action_idx = len(inc.actions)

    def _record_episode(self, inc: Incident, rt: Runtime, outcome: str) -> None:
        if self.experience is None or rt.playbook is None:
            return
        acts = inc.actions[rt.episode_action_idx:]
        if any(a.dry_run for a in acts):
            return                                   # dry runs teach nothing about effectiveness
        now = self.clock.now()
        rt.episode_seq += 1
        run = getattr(self.experience, "run_id", "") or "run"
        eid = f"{run}:{inc.id}#{rt.episode_seq}"
        effective = [a for a in acts if not a.kind.startswith(("notify.", "traffic.release"))]
        ep = Episode(eid, inc.id, inc.asset_id, inc.category.value, inc.signal, rt.playbook.name, rt.episode_start,
                     outcome, reward_for(outcome, len(effective), now - rt.episode_start), now, inc.severity.name,
                     inc.level.name, rt.strategy_attempt, len(effective), rt.explored, run,
                     {"keys": sorted(rt.keys), "trigger": rt.trigger.title, "attempt": inc.attempts})
        self.experience.record_episode(ep, [{"kind": a.kind, "target": a.target, "success": a.success,
                                             "dry_run": a.dry_run, "detail": a.detail} for a in acts])
        rt.last_episode_id = eid
        self._start_episode(inc, rt)

    def _next_strategy(self, inc: Incident, rt: Runtime, why: str) -> None:
        """After a failed attempt: switch to the best untried strategy, else continue progressively."""
        alt = self._choose(inc, rt, exclude=rt.tried) if len(rt.candidates) > 1 else None
        if alt is not None:
            self._apply_choice(inc, rt, alt, "strategy_switch")
            inc.log(self.clock.now(), self._actor(inc), "strategy_reason", why)
        else:
            rt.strategy_attempt += 1

    def _mesh(self, target: str, capability: str, payload: dict) -> Any:
        if self.mesh is None or not self.mesh.has(target, capability):
            return None
        res = self.mesh.call("L3", target, capability, payload)
        return res.value if res.ok else None

    def _check_chronic(self, inc: Incident) -> None:
        now = self.clock.now()
        n = self._mesh("experience", "recurrence", {"asset": inc.asset_id, "signal": inc.signal,
                                                    "since": now - CHRONIC_WINDOW_S})
        if not n or n < self.chronic_threshold:
            return
        topic = f"chronic:{inc.asset_id}:{inc.signal}"
        if self.experience is not None and not self.experience.has_note(topic, now - 86400):
            self.experience.note(now, topic, f"{n} incidents in 7 days")
            self._notify(inc, f"Chronic issue: {inc.signal} on {inc.asset_id} has occurred {n} times in 7 days; "
                              "automation keeps fixing it but it needs a lasting fix", Severity.MEDIUM)
        self._event(inc, "chronic", f"{n} previous incident(s) for this asset and signal in 7 days")

    def _precheck(self, inc: Incident, rt: Runtime, kind: str) -> bool:
        """Ask Level 1 for a fresh look before a MEDIUM+ risk repair. Returns False if the problem is gone."""
        spec = self.policy.spec(kind)
        if (spec is None or spec.risk < 2 or kind in CONTAINMENT_KINDS or inc.category not in PRECHECK_CATEGORIES
                or inc.asset_id not in self.inventory.ids()):
            return True
        res = self._mesh("L1", "rescan", {"asset": inc.asset_id})
        if res is None:
            return True
        if set(res.get("keys", [])) & rt.keys:
            return True
        self._event(inc, "precheck_cleared", f"Level 1 re-scan no longer sees {inc.signal}; skipping {kind}")
        return False

    def _upstream_incident(self, asset_id: str) -> Incident | None:
        if asset_id not in self.inventory.ids():
            return None
        for up in self.inventory.upstream_closure(asset_id):
            for inc in self.active():
                if inc.asset_id == up and inc.category in ROOT_CAUSE_CATEGORIES:
                    return inc
        return None

    # ------------------------------------------------------------------ intake
    def submit(self, level: Level, findings: list[Finding], reason: str,
               verdict: Verdict | None = None) -> Incident | None:
        if not findings:
            return None
        now = self.clock.now()
        head = max(findings, key=lambda f: (f.severity, f.confidence))
        for f in findings:
            if 3 not in f.route and level == Level.L3_DECISION:
                f.route.append(3)
        key = f"{head.asset_id}|{head.category.value}|{head.signal}"

        if key in self.active_by_key:
            inc = self.incidents[self.active_by_key[key]]
            inc.findings.extend(f.id for f in findings if f.id not in inc.findings)
            rt = self.runtime[inc.id]
            rt.fingerprints |= {(f.fingerprint, f.detector) for f in findings}
            if head.severity > inc.severity:
                inc.severity = head.severity
                self._event(inc, "severity_raised", f"now {inc.severity.name}")
            if level > inc.level and inc.level == Level.L2_EVALUATION:
                self._escalate(inc, f"new evidence routed to Level 3: {reason}")
            return inc

        if key in self.failed_by_key:
            # automation already gave up on this condition; do not start it again behind the humans' backs
            inc = self.incidents[self.failed_by_key[key]]
            if len(inc.findings) < 500:
                inc.findings.extend(f.id for f in findings if f.id not in inc.findings)
            return inc

        if head.category in ROOT_CAUSE_CATEGORIES:
            related = next((i for i in self.active() if i.asset_id == head.asset_id
                            and i.category in ROOT_CAUSE_CATEGORIES), None)
            if related is not None:
                rt = self.runtime[related.id]
                # statistical anomalies on a component under mitigation are expected side effects
                # (e.g. throttling lowers requests/s); they are tracked but do not block resolution
                if not head.signal.startswith("anomaly:"):
                    rt.keys.add(key)
                rt.fingerprints |= {(f.fingerprint, f.detector) for f in findings}
                self.active_by_key[key] = related.id
                related.findings.extend(f.id for f in findings if f.id not in related.findings)
                if head.severity > related.severity:
                    related.severity = head.severity
                if level > related.level and related.level == Level.L2_EVALUATION:
                    self._escalate(related, f"correlated evidence routed to Level 3: {reason}")
                self._event(related, "correlated", f"{head.signal} on {head.asset_id} attached as related symptom")
                return related

        if key in self.recent_resolved:
            inc = self.incidents[self.recent_resolved[key]]
            if inc.resolved_at is not None and now - inc.resolved_at <= self.reopen_window:
                del self.recent_resolved[key]
                rt = self.runtime[inc.id]
                inc.status, inc.resolved_at, inc.verify_passes = IncidentStatus.MITIGATING, None, 0
                inc.attempts += 1
                rt.step, rt.trigger = 0, head
                for k in rt.keys:
                    self.active_by_key[k] = inc.id
                    self.recent_resolved.pop(k, None)
                inc.findings.extend(f.id for f in findings)
                if rt.last_episode_id and self.experience is not None:
                    # the previous fix did not hold: that strategy only bought time
                    self.experience.mark_relapse(rt.last_episode_id)
                self._start_episode(inc, rt)
                if inc.attempts > rt.max_attempts:
                    self._fail(inc, "recurred after resolution and attempts are exhausted")
                else:
                    self._event(inc, "reopened", f"signal recurred within {self.reopen_window:.0f}s of resolution")
                    self._next_strategy(inc, rt, "previous strategy's fix relapsed")
                return inc

        candidates = self.playbooks.candidates(head.signal, head.category)
        pb = candidates[0] if candidates else None
        inc = Incident(asset_id=head.asset_id, category=head.category, signal=head.signal, severity=head.severity,
                       opened_at=now, level=level, playbook=pb.name if pb else None,
                       findings=[f.id for f in findings])
        rt = Runtime(pb, head, max_attempts=pb.max_attempts if pb else 1,
                     fingerprints={(f.fingerprint, f.detector) for f in findings}, keys={key},
                     candidates=candidates)
        self.incidents[inc.id] = inc
        self.runtime[inc.id] = rt
        self.active_by_key[key] = inc.id
        inc.attempts = 1
        self._event(inc, "opened", f"{head.title} [{reason}]",
                    {"severity": head.severity.name, "confidence": head.confidence,
                     "rationale": verdict.rationale if verdict else [reason],
                     "playbook": inc.playbook, "evidence": to_jsonable(head.evidence)})
        if candidates:
            choice = self._choose(inc, rt)
            if choice is not None:
                self._apply_choice(inc, rt, choice, "strategy_selected")
                pb = rt.playbook
        self._start_episode(inc, rt)
        self._check_chronic(inc)

        if level == Level.L2_EVALUATION and pb and pb.level > Level.L2_EVALUATION:
            self._escalate(inc, f"playbook {pb.name} requires Level 3 authority")

        root = (verdict.root_cause_asset if verdict else None)
        if inc.category in ROOT_CAUSE_CATEGORIES:
            up = self._upstream_incident(inc.asset_id)
            if up:
                rt.held_by = up.id
                inc.root_cause_asset = up.asset_id
                self._event(inc, "held_as_symptom", f"upstream {up.asset_id} has active incident {up.id}")
                return inc
        if root:
            inc.root_cause_asset = root

        if pb is None:
            inc.level = Level.HUMAN
            self._notify(inc, f"No automated playbook for {inc.signal} on {inc.asset_id}; human decision needed")
            self._event(inc, "handed_to_humans", "no playbook matches this signal")
            return inc
        inc.status = IncidentStatus.MITIGATING
        self._advance(inc)
        return inc

    # ------------------------------------------------------------------ tick
    def tick(self, obs: Observation | None, current_keys: set[str]) -> None:
        self.conflicts.new_tick()
        self.approvals.expire()
        for inc in sorted(self.active(), key=lambda i: (self.runtime[i.id].playbook.priority
                                                        if self.runtime[i.id].playbook else 9, i.opened_at)):
            if inc.level == Level.HUMAN:
                continue
            rt = self.runtime[inc.id]
            if rt.held_by:
                root = self.incidents.get(rt.held_by)
                if root and root.active:
                    continue
                rt.held_by, rt.verify_only = None, True
                inc.status, rt.settle = IncidentStatus.VERIFYING, 0
                self._event(inc, "root_cause_cleared", "upstream incident closed; re-verifying this symptom")
            if inc.status == IncidentStatus.AWAITING_APPROVAL:
                self._check_approval(inc, rt)
            if inc.status in (IncidentStatus.OPEN, IncidentStatus.MITIGATING):
                self._advance(inc)
            elif inc.status == IncidentStatus.VERIFYING:
                self._verify(inc, rt, obs, current_keys)

    # ------------------------------------------------------------------ steps
    def _steps(self, inc: Incident, rt: Runtime):
        assert rt.playbook is not None
        return [s for s in rt.playbook.steps if s.min_attempt <= rt.strategy_attempt]

    def _escalate(self, inc: Incident, why: str) -> None:
        if inc.level >= Level.L3_DECISION:
            return
        inc.level = Level.L3_DECISION
        rt = self.runtime[inc.id]
        if rt.playbook:
            rt.max_attempts = inc.attempts + rt.playbook.max_attempts
        self._event(inc, "escalated", why)

    def _advance(self, inc: Incident) -> None:
        rt = self.runtime[inc.id]
        if rt.playbook is None:
            return
        steps = self._steps(inc, rt)
        while rt.step < len(steps):
            s = steps[rt.step]
            req = ActionRequest(kind=s.kind, target=str(self.render(s.target, inc, rt.trigger)),
                                params=self.render(dict(s.params), inc, rt.trigger), requested_by=inc.level,
                                incident_id=inc.id, rationale=f"{rt.playbook.name} step {rt.step + 1}")
            conflict = self.conflicts.check(req, inc.id, rt.playbook.priority)
            if conflict:
                self._event(inc, "step_deferred", f"{req.kind} on {req.target}: {conflict}")
                return
            if not self._precheck(inc, rt, req.kind):
                rt.step += 1
                continue
            decision = self.policy.evaluate(req, self.inventory.criticality(inc.asset_id))
            if decision.outcome == Outcome.DENY:
                spec = self.policy.spec(req.kind)
                if inc.level == Level.L2_EVALUATION and spec and spec.min_level == Level.L3_DECISION:
                    self._escalate(inc, f"{req.kind} requires Level 3 authority")
                    continue
                self._event(inc, "step_denied", f"{req.kind}: {decision.reason}")
                rt.step += 1
                continue
            if decision.outcome == Outcome.REQUIRE_APPROVAL:
                ap = self.approvals.submit(req, decision.reason, decision.approvals_required)
                rt.waiting = ap.id
                if ap.id not in inc.pending_approvals:
                    inc.pending_approvals.append(ap.id)
                inc.status = IncidentStatus.AWAITING_APPROVAL
                self._notify(inc, f"Approval {ap.id} needed: {req.kind} on {req.target} ({decision.reason})")
                self._event(inc, "approval_requested", f"{ap.id}: {req.kind} on {req.target} - {decision.reason}",
                            {"approval": ap.id, "approvals_required": ap.approvals_required})
                return
            res = self._execute(inc, req, rt.playbook.priority)
            rt.step += 1
            if not res.success:
                break
        inc.status = IncidentStatus.VERIFYING
        rt.settle = rt.playbook.settle_ticks
        inc.verify_passes = 0
        if not rt.playbook.checks or rt.playbook.required_passes == 0:
            self._resolve(inc, "playbook has no verification checks (advisory / notification only)")

    def _execute(self, inc: Incident, req: ActionRequest, priority: int, approved_by: list[str] | None = None
                 ) -> ActionResult:
        self.conflicts.claim(req, inc.id, priority)
        res = self.dispatcher.execute(req)
        self.policy.record_execution(req)
        inc.actions.append(res)
        self.audit.append(self._actor(inc), "action.executed",
                          {"incident": inc.id, "action": req.id, "kind": req.kind, "target": req.target,
                           "params": req.params, "risk": req.risk.name, "success": res.success,
                           "detail": res.detail, "dry_run": res.dry_run, "approved_by": approved_by or []})
        self.bus.publish("action.executed", res)
        inc.log(self.clock.now(), self._actor(inc), "action",
                f"{req.kind} on {req.target}: {'ok' if res.success else 'FAILED'} {res.detail}".strip())
        return res

    def _check_approval(self, inc: Incident, rt: Runtime) -> None:
        if not rt.waiting:
            inc.status = IncidentStatus.MITIGATING
            return
        ap = self.approvals.get(rt.waiting)
        if ap is None or ap.status == ApprovalStatus.PENDING:
            return
        rt.waiting = None
        if ap.status == ApprovalStatus.APPROVED:
            self._event(inc, "approval_granted", f"{ap.id} by {', '.join(ap.approvers)}")
            if not self._precheck(inc, rt, ap.request.kind):
                # the condition cleared while the approval was pending: do not change anything
                rt.step += 1
                inc.status = IncidentStatus.MITIGATING
                return
            res = self._execute(inc, ap.request, rt.playbook.priority if rt.playbook else 9, ap.approvers)
            rt.step += 1
            inc.status = IncidentStatus.MITIGATING
            if not res.success:
                rt.step = len(self._steps(inc, rt))
        else:
            self._event(inc, f"approval_{ap.status.value}", f"{ap.id}: {ap.note}")
            for fp, det in rt.fingerprints:
                if ap.status == ApprovalStatus.REJECTED and ap.note.lower().startswith("false positive"):
                    self.memory.record(fp, det, true_positive=False)
            rt.step += 1
            inc.status = IncidentStatus.MITIGATING

    # ------------------------------------------------------------------ verification
    def _verify(self, inc: Incident, rt: Runtime, obs: Observation | None, current_keys: set[str]) -> None:
        if rt.settle > 0:
            rt.settle -= 1
            return
        pb = rt.playbook
        checks = pb.checks if pb else []
        results = [self.verifier.run(c, inc, obs, current_keys, lambda v: self.render(v, inc, rt.trigger), rt.keys)
                   for c in checks]
        if all(r.ok for r in results):
            inc.verify_passes += 1
            required = pb.required_passes if pb else 1
            if inc.verify_passes >= required:
                self._resolve(inc, "; ".join(f"{r.check}: {r.detail}" for r in results))
            return
        inc.verify_passes = 0
        failed = "; ".join(f"{r.check}: {r.detail}" for r in results if not r.ok)
        effective = [a for a in inc.actions if not a.kind.startswith("notify.")]
        if effective and all(a.dry_run for a in effective):
            self._fail(inc, f"dry-run: remediation plan recorded but not executed; condition persists ({failed})",
                       event="dry_run_handoff")
            return
        if rt.verify_only:
            rt.verify_only = False
            inc.status = IncidentStatus.MITIGATING
            rt.step = 0
            self._event(inc, "symptom_persists", f"{failed}; running own playbook")
            self._advance(inc)
            return
        self._record_episode(inc, rt, "failed")
        if inc.attempts < rt.max_attempts:
            inc.attempts += 1
            rt.step = 0
            inc.status = IncidentStatus.MITIGATING
            self._event(inc, "retry", f"verification failed ({failed}); attempt {inc.attempts}/{rt.max_attempts}")
            self._next_strategy(inc, rt, f"{rt.playbook.name if rt.playbook else '-'} did not pass verification")
            self._advance(inc)
            return
        if inc.level == Level.L2_EVALUATION:
            self._escalate(inc, f"Level 2 remediation exhausted ({failed})")
            inc.attempts += 1
            rt.step = 0
            inc.status = IncidentStatus.MITIGATING
            self._next_strategy(inc, rt, "escalated after Level 2 attempts")
            self._advance(inc)
            return
        self._fail(inc, f"verification failed after {inc.attempts} attempt(s): {failed}")

    def _resolve(self, inc: Incident, detail: str) -> None:
        rt = self.runtime[inc.id]
        now = self.clock.now()
        inc.status, inc.resolved_at = IncidentStatus.RESOLVED, now
        if rt.playbook and rt.playbook.release_valves and any(a.kind.startswith("traffic.") and a.success
                                                              for a in inc.actions):
            req = ActionRequest("traffic.release", inc.asset_id, {"valve": "both"}, Level.L2_EVALUATION, inc.id,
                                rationale="incident verified resolved")
            self._execute(inc, req, rt.playbook.priority)
        self._record_episode(inc, rt, "resolved")
        for fp, det in rt.fingerprints:
            self.memory.record(fp, det, true_positive=True)
        for k in [k for k, v in self.active_by_key.items() if v == inc.id]:
            self.active_by_key.pop(k, None)
        for k in rt.keys:
            self.recent_resolved[k] = inc.id
        self._event(inc, "resolved", detail, {"duration_s": round(now - inc.opened_at, 1),
                                              "actions": len(inc.actions)})

    def _fail(self, inc: Incident, why: str, event: str = "failed") -> None:
        inc.status = IncidentStatus.FAILED
        rolled = 0
        for res in reversed(inc.actions):
            if res.success and res.rollback and not res.dry_run and res.kind not in CONTAINMENT_KINDS \
                    and not res.kind.startswith(("traffic.", "notify.")):
                rb = self.dispatcher.rollback(res)
                rolled += 1
                inc.log(self.clock.now(), self._actor(inc), "rollback",
                        f"{res.kind} on {res.target}: {'ok' if rb.success else 'FAILED'}")
        for k in [k for k, v in self.active_by_key.items() if v == inc.id]:
            self.active_by_key.pop(k, None)
            self.failed_by_key[k] = inc.id
        lead = "Dry run" if event == "dry_run_handoff" else "Automation could not resolve"
        self._notify(inc, f"{lead}: {inc.signal} on {inc.asset_id}: {why}", Severity.HIGH)
        self._event(inc, event, why, {"rolled_back": rolled})

    def _notify(self, inc: Incident, message: str, sev: Severity | None = None) -> None:
        req = ActionRequest("notify.humans", inc.asset_id,
                            {"message": message, "severity": (sev or inc.severity).name}, Level.L3_DECISION, inc.id)
        res = self.dispatcher.execute(req)
        inc.log(self.clock.now(), "notifier", "notified", message if res.success else f"notify failed: {message}")

    # ------------------------------------------------------------------ human operations
    def close_human_incident(self, incident_id: str, by: str, resolution: str, false_positive: bool = False) -> Incident:
        inc = self.incidents[incident_id]
        rt = self.runtime[inc.id]
        inc.status = IncidentStatus.DISMISSED if false_positive else IncidentStatus.RESOLVED
        inc.resolved_at = self.clock.now()
        for fp, det in rt.fingerprints:
            self.memory.record(fp, det, true_positive=not false_positive)
        for k in [k for k, v in self.active_by_key.items() if v == inc.id]:
            self.active_by_key.pop(k, None)
        for k in [k for k, v in self.failed_by_key.items() if v == inc.id]:
            self.failed_by_key.pop(k, None)          # humans closed it: automation may act again
        if inc.asset_id in self.conflicts.containment:
            self.conflicts.release_containment(inc.asset_id)
        inc.log(inc.resolved_at, by, "closed_by_human", resolution)
        self.audit.append(by, "incident.closed_by_human", {"incident": inc.id, "resolution": resolution,
                                                           "false_positive": false_positive})
        return inc
