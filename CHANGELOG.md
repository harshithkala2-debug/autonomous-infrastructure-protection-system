# Changelog

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
