# Architecture

This document maps the concept ([`../autonomous_infrastructure_protection_system_plan.md`](../autonomous_infrastructure_protection_system_plan.md))
onto the implementation.

## Component map

| Concept section | Implementation |
|---|---|
| §2 Level 1: initial detection | `aips/monitoring/detectors.py`: `Level1Fleet` + 8 detector bots |
| §2 Level 2: further evaluation | `aips/evaluation/evaluator.py`: `Level2Evaluator` |
| §2 Level 3: final decision | `aips/decision/engine.py`: `DecisionEngine` |
| §2 Escalation paths | `aips/evaluation/escalation.py`: `EscalationRouter` |
| §3 Specialised bots and repair | detectors, `aips/decision/playbooks.py`, `aips/repair/executor.py` |
| §4 Identity and access protection | `aips/identity/guard.py`: `IdentityGuard` |
| §5 Adaptive operation and repair | `aips/repair/baseline.py` (known-good state), engine verify/retry/rollback |
| §5 Two traffic-control valves | `aips/traffic/valves.py`: `TrafficController`, ingress + internal `Valve` |
| §6 Backup and recovery layers | `aips/backup/{store,vault,manager}.py` |
| §7 External intelligence fleet | `aips/intel/{collectors,versions,relevance,patterns}.py` |
| §8 End-to-end workflow | `aips/orchestrator.py`: `AIPS.tick()` |
| §10 Demonstrations, tests, reproducible evidence | `aips/sim/`, `tests/`, `aips demo`, `aips bench` |
| Any layer dynamically calls another | `aips/core/mesh.py`: `LayerMesh` (capabilities, loop/depth guards) |
| Persistent, rich historical experience | `aips/experience/store.py`: `ExperienceStore` (SQLite) |
| Automatic exploration of strategies | `aips/decision/strategies.py`: `StrategySelector` + playbook variants |

## AI agent guard

`aips/agents/` judges an AI agent's tool calls inline, before they run, and produces findings in category
`agent` that enter the normal hierarchy. CRITICAL or HIGH findings bypass Level 2. Level 3's
`agent-containment` playbook freezes the agent and reverts its file changes through the authorisation policy.
State (calls, freezes, taint, checkpoints, reverts) is in SQLite plus a content-addressed blob store, so the
Claude Code hook, which is one process per call, and a long-running AIPS share the same model. See
[AGENTS.md](AGENTS.md).

## AIPS web, hybrid sandbox and ML (1.5)

`aips/web/` joins machines into one closed trust domain run by one hub (orchestrator).
* Nodes hold only their own HMAC key, connect out and pull jobs.
* Every request and response is signed (domain, node, epoch, time, nonce, method, path, body hash).
* The hub keeps the node registry, routes jobs with leases and failover, quarantines nodes that lie, and stores
  protected objects (write-once, keyed hash-chained index, replicated, self-healing).
* It writes everything to its own tamper-evident ledger and emits findings (`web_intrusion`,
  `web_node_quarantined`, `web_node_anomaly`, `storage_corruption`, `web_fake_approval`), which
  `on_finding=aips.ingest_findings` feeds into the normal hierarchy.
* Human approvals are HMACs made with a key derived from a passphrase that is never stored.

`aips/agents/sandbox.py` runs agent commands after the guard has judged them. They run in a jail copy (local:
Windows low integrity + Job Object; POSIX rlimits + optional network namespace) or on a remote sandbox node, and
reach the real workspace only through checkpointed `promote`.

`aips/ml/` holds a standard-library command-risk model (advisory evidence in the guard) and an Isolation Forest
(hub telemetry). See [WEB.md](WEB.md).

## Layer mesh

```
            ┌──────────── L3.escalate ◄───────────── L1 / identity / backup / intel (bypass)
            │
  Level 3 ──┼── L1.rescan ──► Level 1    (is it still broken? just before a MEDIUM+ risk or approved action)
            ├── experience.recurrence    (chronic issue?)
            │
  Level 2 ──┼── L1.rescan ──► Level 1    (uncertain case: corroborate or refute)
            └── experience.recurrence    (recurring: escalate even if mild)

  API ───────── read-only capabilities only (GET /mesh, POST /mesh/call)
```

## Learning loop

```
 incident opens ─► StrategySelector (canonical | untried | Thompson over ExperienceStore)
       │                    ▲
       ▼                    │ episodes: strategy, outcome, reward, actions, timing
  playbook variant ─► verify ─┬─ pass ─► episode "resolved" ──┐
                              └─ fail ─► episode "failed" ─► switch to best untried variant
  fix relapses within 15 min ─► earlier episode re-scored "relapsed" (0.2) ─► switch variant
```

## Control loop (`AIPS.tick`)

```
 ┌───────────────────────────────────────────────────────────────────────────┐
 │ 0. backup cycle (if due): snapshot main → copy layer; mass-change guard;  │
 │    replicate clean snapshots → vault                                      │
 │ 1. collect: merge Observations from every TelemetrySource                 │
 │ 2. detect: Level 1 fleet + identity findings + backup findings + intel    │
 │ 3. order: upstream assets first; within an asset, most causal signal first│
 │ 4. route: EscalationRouter → Level 2 (standard) or Level 3 (bypass)       │
 │ 5. evaluate: Level 2 verdicts → dismiss / monitor / handle / escalate     │
 │ 6. decide/act: DecisionEngine.submit(...) → playbook → policy → dispatch  │
 │ 7. progress: DecisionEngine.tick → approvals, verification, retry, fail   │
 │ 8. valves: ramp open where the component shows no non-statistical signal │
 │ 9. learn + audit: outcome memory, hash-chained ledger, bus events         │
 └───────────────────────────────────────────────────────────────────────────┘
```

The loop is deterministic for a given input and clock. This is what makes simulator runs reproducible
(`tests/test_system.py::test_deterministic`).

## Data model (`aips/core/models.py`)

* `Finding`: detector, category, severity, confidence, asset, signal, evidence[], tags, route (levels visited),
  and a stable `fingerprint`.
* `Verdict`: Level 2 judgement of a case: disposition, combined confidence, rationale[], root-cause asset.
* `Incident`: status machine, level, playbook, findings, actions, approvals, timeline, attempts.
* `ActionRequest` / `ActionResult`: the only form in which a decision can affect infrastructure.

## Incident state machine

```
             submit()
                │
                ▼
   ┌──────── OPEN ─────────┐  held_as_symptom (upstream incident active)
   │            │          └────────────► wait ─► root_cause_cleared ─► VERIFYING (verify-only)
   │            ▼
   │       MITIGATING ──► step needs approval ──► AWAITING_APPROVAL ──► approved/rejected/expired
   │            │                                         │
   │            ▼                                         │
   │        VERIFYING ◄───────────────────────────────────┘
   │        │       │
   │  pass×N│       │fail
   │        ▼       ▼
   │   RESOLVED   attempts left? ──yes──► MITIGATING (attempt+1, progressive steps)
   │     │                 │no
   │     │                 ├── level L2 ──► ESCALATED to L3 (more attempts, more authority)
   │     │                 └── level L3 ──► FAILED: roll back reversible actions, notify humans
   │     └── signal recurs within reopen window ──► reopened (same incident, attempt+1)
   └── no playbook ──► handed to humans (level HUMAN)
```

## Correlation rules

1. **Same asset, causal ordering.** If several availability, performance or capacity signals fire on one asset in
   the same cycle, the most causal one opens the incident (see `SIGNAL_PRECEDENCE`, e.g. `overload` before
   `error_rate_critical`). The others attach as correlated symptoms, and the incident only resolves when all
   non-statistical signals have cleared.
2. **Dependency graph.** If an upstream dependency has an active availability incident, a downstream incident is
   *held as a symptom*. When the root cause resolves, the symptom is re-verified and only remediated if it persists.
3. **Statistical anomalies never remediate on their own.** They are expected while AIPS is mitigating an asset (for
   example, throttling lowers requests/s). Sustained level shifts are absorbed as the new normal. Recurring,
   unexplained, intermittent anomalies escalate to a human.
4. **Conflicts.** Incidents are processed in playbook priority order. Mutually exclusive actions on the same target
   in the same cycle defer the lower-priority one, and a contained (isolated) target receives no availability actions.

## Extension points

| To add… | Implement / register |
|---|---|
| a telemetry source | `TelemetrySource.collect(now) -> Observation` |
| a detector bot | `Detector.detect(obs, ctx) -> list[Finding]`, add to `Level1Fleet` |
| a playbook | `Playbook(name, signals, level, steps, checks, priority)` in a `PlaybookLibrary` |
| an action kind | `ActionSpec` in the policy catalogue + adapter support |
| an infrastructure integration | `InfrastructureAdapter.execute / rollback / health` |
| an intel source | return `Advisory` / `IncidentReport` objects; `merge_advisories` de-duplicates |
| a failure pattern | `FailurePattern(id, name, keywords, check, recommendation)` in `PATTERNS` |
| a distributed bus | implement `EventBus.publish/subscribe` over Kafka/NATS |
