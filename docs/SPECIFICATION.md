# Technical specification

This document specifies each topic that concept §11 listed as "to be written into a complete technical
specification". Each section gives the behaviour, the defaults and the code that implements it.

---

## 1. Bot roles and responsibilities

| Bot | Level / fleet | Input | Output | May act? |
|---|---|---|---|---|
| `l1.health` | L1 | service liveness probes | `service_down` (confidence 1-0.35ⁿ over n consecutive failures) | no |
| `l1.threshold` | L1 | metrics | `error_rate_high/critical`, `latency_high`, `cpu_saturated`, `overload`, `disk_full`, `memory_pressure`, `replication_lag` | no |
| `l1.anomaly` | L1 | metrics | `anomaly:<metric>` (EWMA z-score ≥ 3.5 after 12 samples; level-shift absorption after 10) | no |
| `l1.forecast` | L1 | disk history | `disk_forecast` (least squares; r² ≥ 0.6; time-to-full < 6 h) | no |
| `l1.drift` | L1 | config snapshots + baseline | `config_drift` (SECURITY when a security-sensitive key changed) | no |
| `l1.exposure` | L1 | open ports + inventory allow-list | `unexpected_port` | no |
| `l1.certs` | L1 | inventory certificates | `cert_expiry` (≤30 d MEDIUM, ≤7 d HIGH, expired CRITICAL) | no |
| `l1.external` | L1 | alerts from IDS/EDR/CSPM | any signal | no |
| `id.guard` | identity fleet | access events | `boundary_violation`, `credential_misuse`, `identity_anomaly`; enforces deny | denies requests outside the boundary |
| `backup.guard` | backup fleet | snapshot diffs | `mass_encryption` | holds vault replication |
| `intel.relevance` | intel fleet | advisories, reports, inventory | `vulnerable_component`, `possible_exposure`, `intel_pattern:<id>` | no |
| `l2.evaluator` | L2 | findings + context | `Verdict` | through Level 2 playbooks only |
| `l3.decision` | L3 | escalations, bypass findings | incidents, action requests | through policy |

## 2. How bots exchange data and coordinate

* **Transport.** `EventBus` (in-process pub/sub, topic wildcards, dead-letter isolation). Topics: `finding.l1`,
  `verdict.<disposition>`, `incident.<event>`, `action.executed`, `valve.changed`.
* **Ordering.** The orchestrator processes each cycle deterministically. Upstream assets come first, then signals
  in causal order on each asset.
* **Shared state.** Read-only inventory, a baseline store, outcome memory and valve positions. Only the action
  dispatcher mutates infrastructure.
* **Distributed deployments.** The bus interface is deliberately small (`publish`, `subscribe`) so that it can be
  backed by Kafka, NATS or Redis Streams.

## 3. Evidence each level receives

* **Level 1 → router:** a `Finding` with `evidence[]` (raw metric, diff, probe result, access event, advisory) and
  `confidence`.
* **Router → Level 2:**
  * every finding in the case (`asset|category|signal`) over the correlation window (300 s)
  * every finding on the same asset from *other* detectors (corroboration, combined by noisy-OR)
  * dependency-graph impairment state
  * maintenance windows and suppressions
  * outcome-memory precision
* **Level 2 → Level 3:** the `Verdict` (disposition, combined confidence, rationale[], root-cause asset) plus all
  of its findings.
* **Level 3 → humans:** an approval request with the action, target, params, risk, reason and incident link.
  Each incident carries a full timeline with an audit record for every step.

## 4. Escalation criteria and severity definitions

| Severity | Meaning | Examples |
|---|---|---|
| INFO | context only | expired transient case |
| LOW | hygiene; no user impact | possible exposure (version unknown), single anomaly |
| MEDIUM | degradation or risk; impact unlikely in the next hour | elevated errors, drift, cert < 30 d |
| HIGH | user impact or likely exploitation | service down, overload, security drift, boundary violation |
| CRITICAL | severe impact or active attack on critical assets | critical asset down, mass encryption, KEV-listed CVSS ≥ 9 |

Severity is raised one step for criticality-5 assets and lowered one step for criticality-1 assets.

**Bypass to Level 3** (`EscalationConfig`) applies when any of the following holds:
* the finding is CRITICAL with confidence ≥ 0.5
* the finding is HIGH with confidence ≥ 0.9
* the finding is in the SECURITY, IDENTITY or DATA_INTEGRITY category, at HIGH or above, with confidence ≥ 0.75

**Level 2 dispositions** (`EvaluatorConfig`). These are evaluated in order:
1. suppression → DISMISS
2. maintenance window → MONITOR (except critical security/identity)
3. upstream impaired → MONITOR (symptom)
4. flapping ≥ 4 → ESCALATE
5. confidence < 0.30 → DISMISS
6. one-shot assessment (intel/backup) with a Level 2 playbook → HANDLE
7. LOW severity with < 3 occurrences → MONITOR
8. anomaly: under mitigation → MONITOR; < 12 occurrences → MONITOR; otherwise → ESCALATE
9. HIGH with confidence ≥ 0.6 → ESCALATE
10. a Level 2 playbook exists and confidence ≥ 0.5 → HANDLE
11. MEDIUM with confidence ≥ 0.6 → ESCALATE
12. anything else → MONITOR

## 5. Which actions each bot is authorised to perform

`aips/core/policy.py::DEFAULT_CATALOG`:

| Action | Risk | Reversible | Minimum level | Notes |
|---|---|---|---|---|
| notify.humans | NONE | yes | L1 | 60/h |
| service.restart | LOW | yes | L2 | 6/h per target |
| service.scale_out | LOW | yes | L2 | |
| storage.cleanup | LOW | **no** | L2 | allow-listed paths only |
| traffic.throttle / release | LOW | yes | L2 | |
| backup.hold_replication | LOW | yes | L2 | |
| cert.renew | LOW | yes | L2 | |
| storage.expand | MEDIUM | yes | L3 | |
| config.restore_baseline | MEDIUM | yes | L3 | |
| traffic.restrict | MEDIUM | yes | L3 | |
| identity.freeze | MEDIUM | yes | L3 | appealable |
| identity.revoke_sessions | MEDIUM | **no** | L3 | |
| identity.revert_actions | MEDIUM | yes | L3 | disables/removes what a contained identity created; undoable |
| agent.freeze | MEDIUM | yes | L3 | AI agent: every further tool call refused |
| agent.revert_actions | MEDIUM | yes | L3 | restores files an agent changed since it misbehaved; undoable |
| network.block_port | MEDIUM | yes | L3 | |
| host.isolate | HIGH | yes | L3 | two approvers by default |
| backup.restore | HIGH | **no** | L3 | always approval, two approvers |
| package.upgrade | HIGH | yes | L3 | always approval, two approvers |
| identity.unfreeze | LOW | yes | HUMAN | appeal outcome |
| agent.unfreeze | LOW | yes | HUMAN | a human releases a frozen agent |

Autonomy ceiling is `max_autonomous_risk = MEDIUM` by default. Criticality-5 assets need approval for MEDIUM or
higher risk. Targets matching `protected_targets` always need approval.

## 6. How repair actions are checked

Every playbook declares `checks` (`healthy`, `metric_below`, `config_matches`, `port_closed`, `identity_frozen`,
`signal_clear`). After the steps run, the incident waits `settle_ticks` cycles and must then pass every check on
`required_passes` consecutive cycles (default 2).

* **On failure:** the next attempt runs, adding progressive steps marked with `min_attempt`.
* **When attempts are exhausted:** a Level 2 incident escalates to Level 3. A Level 3 incident FAILS: successful
  reversible actions are rolled back in reverse order (containment excepted) and humans are paged.
* **Rate limits** stop runaway repair loops: after the 6th restart of a target within an hour, the next one
  needs approval.
* **Failed stays failed:** once an incident has FAILED, later findings for the same condition attach to it.
  Automation does not start again until a human closes the incident (`POST /incidents/{id}/close`).
* **Dry run:** if every effective action in an incident was a dry run, a failed verification hands the incident
  to humans straight away (`dry_run_handoff`). It does not "retry" actions that never ran. The recorded plan is
  the output.

## 7. Handling conflicting findings

* **Contradictory evidence about one case.** Corroboration (noisy-OR) and outcome-memory precision decide the
  combined confidence. Level 2 can dismiss the case.
* **Several signals on one asset.** The causal-precedence ordering decides which one opens the incident; the
  others attach to it.
* **Upstream versus downstream.** The root-cause rule holds the dependents as symptoms.
* **Competing actions on one target.** Playbook priority decides: containment (0) > integrity (1) >
  availability (2) > performance (3) > hygiene (4). The lower-priority step is *deferred*, not dropped, and an
  isolated target accepts no availability actions.
* **A human disagrees.** A rejection whose note starts with "false positive", or a granted appeal, is recorded
  in outcome memory as a false positive.

## 8. How decisions and changes are recorded

`AuditLedger` (`aips/core/audit.py`) appends JSON lines with `seq`, `ts`, `actor`, `event`, `payload`, `prev`
and `hash`, where `hash = HMAC-SHA256(key, canonical(body))`. Each record therefore chains to the previous one,
and an attacker who does not hold the key cannot alter, delete or reorder records without detection
(`aips audit verify`). Recorded events:

* `aips.started`
* every `verdict.*` transition
* `incident.*` (opened, escalated, correlated, held, approval requested/granted/rejected, retry, resolved, failed)
* `action.executed` with params, risk, result and approvers
* `approval.*`, `appeal.*`, `baseline.captured`, `killswitch.*`, `intel.assessed`

## 9. How the two traffic-control valves operate

* **Ingress valve:** limits external requests into the component.
* **Internal valve:** limits internal streams such as replication, queue consumers and batch jobs.
* **Position** runs from 0 to 1. The admitted rate is `capacity_rps × position`, enforced by a token bucket with
  one second of burst.
* **Shedding by priority:**
  * ≥ 0.5 → all traffic, rate-limited
  * 0.2 – 0.5 → BULK traffic shed
  * < 0.2 → CRITICAL only
  * 0 → shut (only via isolation or a human)
* **Autonomous floor:** 0.1, so a bot can never fully black-hole a service.
* **Relationship to repair:** playbooks close valves *before* repairing (for example, `service-recovery` sets
  ingress to 0.3 and `overload-protection` sets ingress 0.5 and internal 0.6). When the incident resolves,
  `traffic.release` starts an AIMD ramp: +0.25 per healthy cycle, ×0.5 on regression. Regression means any
  non-statistical finding on the asset.
* **Integration:** the `apply_valve(asset, kind, position)` adapter hook pushes positions to gateways (Envoy,
  NGINX, API gateway) or consumers. `Valve.admit()` can be used in-process.

## 10. Backup frequency, retention, isolation and restoration

* **Frequency:** `interval_s` (default 1 h) incremental snapshots. Content-addressed storage means unchanged files
  cost nothing.
* **Detail:** every file is stored in full (path, size, mode, mtime, SHA-256) in a manifest signed with HMAC.
  Objects are zlib-compressed and optionally AES-256-GCM encrypted. Each read re-hashes the content.
* **Isolation:** the vault lives in a separate root (a separate volume, host or account in production).
  * Every operation passes an IP allow-list gate for the organisation's networks.
  * Audit records carry only a salted hash of the caller's IP.
  * Objects and manifests are write-once (read-only files).
  * A retention lock (default 30 days) blocks deletion, even by AIPS.
* **Mass-change guard:** a snapshot is flagged *suspect* when ≥ 30 % of files changed and either the changed
  content has entropy ≥ 7.2 bits/byte or files were renamed with ransomware extensions. A suspect snapshot is
  never replicated and never chosen as `latest_clean`, and it raises a CRITICAL finding.
* **Retention:** grandfather-father-son. Keep the last 24 snapshots, 7 daily, 4 weekly and 6 monthly. Suspect
  snapshots are kept for forensics.
* **Restoration:**
  * restore from the copy layer or the vault, with path-traversal protection, atomic writes and post-restore
    hash verification
  * `clean_target` removes files that are not in the snapshot (for example, `.locked` files)
  * restore drills (`restore_drill`) prove restorability on a schedule, and the intel fleet flags stale drills

## 11. How external reports are checked for relevance and accuracy

* **Source reliability weights:** CISA KEV 0.98, NVD 0.95, OSV 0.9, vendor 0.9, postmortem 0.75, blog 0.6.
  The weight scales confidence.
* **De-duplication:** advisories are merged across CVE IDs and aliases. KEV adds `known_exploited` and ransomware use.
* **Version matching:** names are normalised (with aliases) and the vendor is checked. The installed version is
  tested against `start/end including/excluding` and exact ranges using a tolerant comparator that handles
  epochs, pre-releases and letter suffixes:
  * inside a range → *confirmed*
  * product matches but there is no range data → *possible* (LOW; a human must confirm the version)
  * outside every range → *not affected*
* **Enrichment:** KEV entries carry no version data. When one names installed software, `enrich_from_nvd` fetches
  that CVE's NVD record and uses its version ranges, so the result becomes *confirmed* or *not affected* instead
  of *possible*.
* **Severity:** taken from CVSS, raised one step if KEV-listed and one step if the asset is internet-facing.
* **Postmortems:** reports are parsed from RSS/Atom (entity declarations are rejected and size is bounded) and
  matched against a keyword taxonomy of failure patterns. **A pattern produces a finding only when its environment
  check finds the condition in this inventory.** The report alone never does.
* **Network hygiene:** HTTPS only, timeouts, a 25 MB cap, per-host rate limiting, an on-disk cache, and a
  User-Agent without personal data.

## 12. Deployment, scaling and integration requirements

* Python ≥ 3.11 with no runtime dependencies (`cryptography` is optional). A Docker image runs as a non-root user.
* A single process handles thousands of assets per 30-second cycle. Detector cost is linear in metric count.
* **Horizontal scaling:** shard by asset group, with one orchestrator per shard. Put the bus behind Kafka/NATS and
  share the audit sink.
* **Integration:**
  * telemetry through JSONL or a custom `TelemetrySource`
  * actions through `CommandAdapter` templates or a custom adapter
  * identity events through `POST /access-events` (from an IdP, cloud audit logs or a proxy)
  * alerts through `POST /findings`
  * metrics through `GET /metrics`
* **Secrets:** environment variables only (`*_env` keys). The API token must be at least 16 characters.

## 13a. Dynamic inter-layer calls (layer mesh)

`aips/core/mesh.py::LayerMesh`. Every layer registers named capabilities, and any layer can call any other
with `mesh.call(caller, target, capability, payload)`. The fixed pipeline (L1 → L2 → L3) is only the default path.

| Capability | Provided by | Used by | Why |
|---|---|---|---|
| `L1.rescan` | Level 1 (fresh, side-effect-free detection pass on one asset) | Level 2, Level 3, API | L2: corroborate or refute an uncertain case. L3: confirm the problem still exists before a MEDIUM+ risk action, and again before running an approved action. |
| `L1.probe` | Level 1 / adapter | any | direct liveness check |
| `L2.case` | Level 2 | any | Level 2's current view of an asset |
| `L3.escalate` | Level 3 | Level 1, identity, backup and intel fleets | the bypass: a producing layer opens or updates an incident directly |
| `L3.incidents` | Level 3 | any | incidents for an asset |
| `experience.recurrence / similar / strategy_stats / summary` | experience store | Level 2, Level 3, API | history-aware decisions |
| `identity.status`, `traffic.state`, `backup.status` | the fleets | any | cross-fleet context |

Safety properties:
* A call already on the current call stack (same target, capability and payload) is refused, so A → B → A
  loops cannot happen.
* Calls deeper than `max_depth` (4) are refused.
* A failing capability returns an error result; it never raises into the caller.
* Every call is counted and logged (`GET /mesh`). Capabilities marked `mutating` are written to the audit ledger.
* The HTTP API can call only read-only capabilities.

## 13b. Persistent historical experience

`aips/experience/store.py::ExperienceStore` is a SQLite database (`[experience] path`, default
`<data_dir>/experience.db`). It survives restarts and is shared by every run that points at it.

| Table | Contents |
|---|---|
| `episodes` | one row per attempt to fix an incident with one strategy: asset, signal, category, severity, level, strategy, start/end, outcome (`resolved`, `failed`, `relapsed`, `handed_off`), reward, attempt, number of actions, whether it was exploratory, run id, context |
| `actions` | every action of every episode, with its result |
| `detector_outcomes` | true- and false-positive counts per detector and per finding fingerprint. This is the persistent form of outcome memory and feeds Level 2's confidence calibration. |
| `notes` | annotations such as chronic-issue notices (de-duplicated per day) |

**Reward.** A resolution scores about 1, minus a small cost per action (0.03, capped at 0.25) and per hour to
resolve (capped at 0.15). A fix that *relapses* within the reopen window is re-scored to 0.2. Failures score 0.
Dry-run episodes are never recorded, because they say nothing about how well a strategy works.

**How history is used:**
* **Level 2:** an asset and signal with 3 or more incidents in 7 days is escalated as *chronic*, even when each
  occurrence is mild.
* **Level 3:** a chronic issue triggers a one-per-day human notice ("automation keeps fixing it, but it needs a
  lasting fix").
* **Strategy selection** (§13c).
* **Detector confidence calibration.**

## 13c. Automatic strategy exploration

`aips/decision/strategies.py::StrategySelector`. Signals can have several playbook *variants*:

| Signal family | Variants (canonical first) |
|---|---|
| `service_down`, `error_rate_critical` | service-recovery, restart-only, scale-then-restart |
| `error_rate_high` | elevated-errors, restart-early |
| `overload`, `cpu_saturated`, `latency_high` | overload-protection, scale-first, shed-load |
| `disk_forecast`, `disk_full` | storage-pressure, expand-first |

**Selection:**
1. With no history for the signal, the expert-reviewed **canonical** variant is used.
2. Any variant never tried yet is tried once (**forced exploration**).
3. After that, **Thompson sampling** applies. Each variant has a belief Beta(1 + Σreward, 1 + Σ(1 − reward)),
   with episodes on the same asset weighted ×2. One sample is drawn from each belief and the highest sample wins.
   Strong variants are therefore used more and more often, while uncertain ones still get an occasional chance.
4. **Inside one incident:** when an attempt fails verification, or a fix relapses, the next attempt switches to
   the best variant not yet tried in that incident.

**Limits on exploration:**
* **Known-bad floor:** a variant whose recent mean reward is below 0.5 is not chosen while a viable alternative
  exists. Mid-incident, AIPS never falls back to such a variant; the current strategy moves on to its next,
  more thorough steps instead.
* **Evidence horizon:** only the last 90 days of episodes count, so a bad verdict is not permanent and a strategy
  becomes eligible again once its old evidence ages out.
* Playbooks with containment or data-integrity priority are never explorable.
* Criticality-5 assets always use the canonical or best-known variant.
* Every step of every variant still passes the authorisation policy, so exploring can never gain more autonomy.
* Selection is seeded (`[strategy] seed`), so runs are reproducible.

## 13d. Protecting AI agents

AI agents are treated as a protected actor in their own right. `aips/agents/` judges each tool call *before*
it runs:
* the inputs are the tool, its arguments, the session and the working directory;
* the signals are harm rules, the agent's policy, behaviour, and prompt-injection taint from earlier outputs;
* the verdict is ALLOW, FLAG, ASK or BLOCK.

Non-ALLOW verdicts produce findings in category `agent` (signals `agent_harmful_action`, `agent_injection`,
`agent_erratic`, `agent_policy_violation`). These enter the hierarchy like any other finding. The
`agent-containment` playbook (containment priority, never explored) runs `agent.freeze` → `agent.revert_actions`
→ `notify.humans`. Success is checked with `agent_frozen`. Files are checkpointed before any change, and a
revert restores from the agent's first flagged call onward. Full behaviour, integrations and limits:
[AGENTS.md](AGENTS.md).

## 13. Test scenarios, benchmarks and success criteria

See [`TESTING.md`](TESTING.md). Every scenario has explicit, machine-checked success criteria. `aips bench`
reports pass rate, mean and p95 time to detect and resolve, action counts and false-positive incidents across
seeds.
