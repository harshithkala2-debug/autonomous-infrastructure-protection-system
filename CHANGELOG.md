# Changelog

## 1.3.0

Closes the gaps found by the first live Google Cloud field test. All verified live except the human-account
freeze (see `docs/FIELD_TEST_GCP.md`).

* **Revert what a contained identity did.** New action `identity.revert_actions` (MEDIUM, Level 3), added to the
  identity-containment playbook.
  * The identity guard now keeps a per-identity action history with platform details.
  * After a freeze, actions from the identity's first suspicious action onward are reversed: created service
    accounts and keys are disabled, added project role grants are removed, created firewall rules are disabled.
  * Read-only calls are skipped; anything else goes to a human for review.
  * Every revert can be undone (rollback), but it is never auto-undone when an incident fails.
* **Late audit events.** Frozen identities are re-checked every cycle; actions that appear in the audit log after
  the freeze are reverted too, through the policy gate.
* **Freezing human accounts in Google Cloud.** Removes the principal's project role bindings, saves them for an
  exact restore on appeal, and refuses to remove the last human owner.
* Cloud Audit Log parsing captures created resources (`response.email` / `response.name`) and IAM binding deltas.
  It never keeps key material.
* Emulator: project IAM policy, key disable/enable, audit entries with responses and policy deltas. 5 new tests.

## 1.2.1

First **live Google Cloud field test**: a misuse was disabled in real IAM in 31 s, and 6 of 6 live safety tests
passed. See `docs/FIELD_TEST_GCP.md`. Bugs it found, all fixed:

* Discovery no longer aborts when the Compute Engine API is unavailable (for example, a project without
  billing); identity protection runs regardless.
* A granted appeal now restores access **on the platform** (re-enables the service account in IAM), not only
  inside AIPS.
* Invalid or expired credentials at start-up no longer crash AIPS. It starts, records the error, retries every
  cycle, and merges discovered assets into the inventory once discovery succeeds. New VMs are picked up
  continuously.

## 1.2.0

* **Google Cloud integration** (`aips/integrations/gcp`, REST APIs, no Google SDK):
  * credential chain: token, service-account key, gcloud, metadata server;
  * client with retries, pagination and operation polling;
  * discovery of VMs, MIGs, firewall rules and service accounts into an inventory;
  * telemetry from Cloud Monitoring, VM/MIG state, firewall-rule drift, internet exposure (computed with
    Google's priority and deny-wins semantics), Cloud Audit Logs fed to the identity guard, and Security Command
    Center findings;
  * actions with rollbacks: VM reset, MIG restart/resize, deny rules, quarantine tag, firewall restore that
    disables (never deletes) unapproved rules, and service-account disable/enable as the platform side of an
    identity freeze.
* In-process Google Cloud API emulator and 15 tests, including end-to-end runs: a rogue firewall rule is
  contained and reverted, a crashed MIG is restarted, and a misused service account is disabled in IAM.
* `aips gcp check | discover | baseline`, `examples/aips-gcp.toml` and the `docs/GCP.md` walkthrough.
* Access events from telemetry now reach the identity guard. The guard can register principals it has never
  seen and judge them by behaviour (`learn_identities`).

## 1.1.1

* **License change:** AIPS is now proprietary, evaluation-only software (AIPS Evaluation License, all rights
  reserved). Reading and unmodified test-environment evaluation are allowed; everything else needs the owner's
  prior written permission. Added NOTICE.md and a *Permission request* issue template.
* Strategy selection never picks a variant history shows to be bad while a viable one exists; evidence older than
  90 days ages out.
* Time-to-detect counts only findings at or after the fault.
* CI matrix trimmed for private-repository Actions minutes.

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
