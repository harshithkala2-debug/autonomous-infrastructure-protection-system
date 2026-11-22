# Changelog

## 1.1.0

* **Layer mesh.** Any layer can dynamically call any other through registered capabilities, with discovery,
  loop and depth refusal, contained failures, statistics and an audit trail.
  * Level 2 asks Level 1 for a fresh re-scan when a case is uncertain.
  * Level 3 re-checks with Level 1 before MEDIUM+ risk actions and before running an approved action.
  * The bypass now calls `L3.escalate` directly.
* **Persistent experience.** A SQLite `ExperienceStore` records every episode (strategy, actions, outcome,
  reward, timing, relapse) plus detector outcomes, and survives restarts. It drives chronic-issue escalation and
  persistent confidence calibration.
* **Strategy exploration.** Playbook variants for service failure, elevated errors, overload and disk pressure.
  * Selection: canonical on cold start, forced trial of untried variants, then Thompson sampling.
  * Inside an incident, AIPS switches to an untried variant on failure or relapse.
  * Never explores containment or integrity responses, or criticality-5 assets.
* New scenarios: `strategy_learning`, `transient_drift`, `experience_carryover`.
* New API endpoints `/mesh`, `/mesh/call` (read-only) and `/experience`; new CLI command `aips experience`;
  new config sections `[experience]` and `[strategy]`.

## 1.0.1

Found by the first live dry run on a real workstation:

* Fix: a FAILED incident no longer respawns as a new incident while its condition persists; it stays with humans
  until closed.
* Dry run: incidents are handed off once with their recorded plan (`dry_run_handoff`) instead of retrying
  actions that were never executed.
* Intel: `enrich_from_nvd` resolves version-less CISA KEV entries against NVD ranges for installed software.
* Host telemetry: listening TCP ports via `netstat` (Windows/Linux/macOS), enabling the exposure bot on real hosts.
* CLI: `aips run --ticks N --tick-seconds S --report FILE`.

## 1.0.0

First complete release.

* Three-level detection, evaluation and decision hierarchy with severity-based bypass.
* Eight Level 1 detector bots; Level 2 evaluator with corroboration, root-cause analysis, maintenance windows,
  suppression, flapping detection and outcome learning.
* Level 3 decision engine with playbooks, progressive remediation, verification, retry, escalation, rollback,
  conflict resolution and symptom correlation.
* Authorisation policy with risk tiers, autonomy ceiling, protected targets, rate limits, a two-person rule,
  a kill switch and dry-run mode.
* Identity guard with permission boundaries, behaviour profiles, risk scoring, freeze/revoke and appeals.
* Two traffic-control valves per component, with priority shedding and AIMD ramping.
* Layered backup: content-addressed copy layer, signed manifests, IP-gated write-once vault with retention lock,
  ransomware mass-change guard, GFS retention, verified restore and restore drills.
* External intelligence: NVD, CISA KEV, OSV and RSS/Atom collectors; version-range relevance; failure-pattern
  environment checks.
* HMAC hash-chained audit ledger, REST control plane, Prometheus metrics, CLI, Docker image.
* Deterministic simulator with 14 scenarios, benchmark harness, and a 60-test suite.
