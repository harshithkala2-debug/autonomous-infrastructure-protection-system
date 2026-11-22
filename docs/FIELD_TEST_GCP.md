# Field test: AIPS on a live Google Cloud project

**Date:** 22 November 2026 · **AIPS version:** 1.2.x · **Result:** 6 of 6 live tests passed after fixes; 3 real
bugs found and fixed.
**Raw data (sanitised):** [`field-tests/gcp-live-2026-11-22.json`](field-tests/gcp-live-2026-11-22.json)

## Summary

AIPS ran against a real Google Cloud project, not the simulator or the emulator. It read Google's real audit
logs, decided on its own, and changed real IAM state through Google's APIs.

* A staged misuse of a service account was **detected 24–55 seconds after it happened**. In the main run the
  account was **frozen and disabled in Google IAM 31 seconds after the misuse**, verified and resolved at
  47 seconds. Google confirmed independently that the account was disabled.
* **No false positives on legitimate activity:** 41 legitimate events from the project owner, plus a dedicated
  legitimate-activity test, raised no incidents.
* All the safety controls behaved correctly on the real platform: dry run, protected identities, kill switch
  with human approval, and the appeal process (self-approval refused, access restored in IAM).
* Live testing found **three real bugs that the emulator and simulator had not exposed**. All are fixed, with
  regression tests.

## Setup

| Item | Value |
|---|---|
| Project | Dedicated test project `aips-lab-XXXXXX`, **no billing account** (zero cost). Deleted after the test. |
| APIs used | IAM, IAM Service Account Credentials, Cloud Logging. Compute Engine needs billing, so the infrastructure half was tested against the emulator instead (see [TESTING.md](TESTING.md)). |
| AIPS | Running on a Windows workstation; credentials via the `gcloud` CLI (the owner signed in once); `dry_run = false` |
| Target identity | `app-sa`, a deliberately over-privileged service account (allowed to create service accounts), with an AIPS boundary that permits only `storage.objects.*` from `10.0.0.0/8` |
| Staged misuse | Acting as `app-sa` (impersonation) from the workstation's public IP: create a new service account. No key files were created. |
| Verification | Every outcome was checked independently with `gcloud`, from Google's side, not only from AIPS's own records |

## Main live run (9 minutes, autonomous)

| Time | Event |
|---|---|
| 19:29:20 | AIPS starts; reads 14 recent audit events from the owner's setup work and raises **no** incidents |
| 19:29:51 | **Misuse:** `app-sa` creates a service account from an address outside its allowed network |
| 19:30:22 | **+31 s:** the misuse is read from the real audit log. Boundary violation (method outside boundary, foreign network, IAM-sensitive action) → HIGH → bypass to Level 3 → `identity-containment`. Identity frozen, **service account disabled in Google IAM**, sessions revoked, humans notified. |
| 19:30:38 | **+47 s:** verification passes (`identity_frozen`) and the incident is resolved |
| afterwards | `gcloud` confirms `disabled: True`. An attempt to act as `app-sa` fails with Google's *"Account disabled"*, and AIPS records that attempt as *denied (frozen)*. |

Totals for the run: 43 audit events read, 41 allowed, 1 boundary violation, 1 freeze, 1 denied attempt,
0 API errors, audit hash chain verified.

## Live test suite

Each test used a fresh AIPS instance and staged its own event *after* AIPS started.

| # | Test | Result | Measured |
|---|---|---|---|
| L1 | Autonomous freeze, then appeal: self-approval refused, a different reviewer grants it, access restored in IAM | **PASS** | detected and frozen 24 s after staging; re-enabled in IAM, verified with gcloud |
| L2 | Legitimate admin activity by the owner (create, list and delete a service account) | **PASS** | 5 real events read, **0 incidents** |
| L3 | Dry run: the freeze is *planned and recorded*; nothing may change in IAM | **PASS** | detected at 23 s; account stayed enabled |
| L4 | Protected identity: no automatic disable; a human approval is requested instead | **PASS** | detected at 24 s; approval requested; account stayed enabled |
| L5 | Kill switch: nothing happens until a human approves, then the account is disabled, then an appeal restores it | **PASS** | approval requested at 55 s; enabled while pending, disabled after approval, enabled after appeal |
| L6 | Invalid credentials: clean failure, no crash, nothing changed | **PASS** | `aips gcp check` reports HTTP 401 per API; AIPS keeps running and records the error |

## Bugs found by live testing, and fixed

| # | Bug | Impact | Fix |
|---|---|---|---|
| 1 | Discovery aborted when the Compute Engine API was unavailable (for example, a project without billing) | Identity protection could not run at all in such a project | Compute is now optional in discovery; IAM and audit-log protection run regardless |
| 2 | Granting an appeal unfroze the identity **inside AIPS only**; the service account stayed disabled in Google IAM | A wrongly frozen user would stay locked out on the platform | A granted appeal now runs `identity.unfreeze` through the action dispatcher, which re-enables the account in IAM (verified live in L1 and L5) |
| 3 | Invalid or expired credentials at start-up **crashed AIPS** during discovery | One token problem took down the whole protection system | AIPS starts anyway, records the error, retries discovery every cycle, and merges assets into its inventory once discovery succeeds. Newly created VMs are now picked up automatically too. |

Earlier, the emulator-based tests had already found and fixed a fourth bug: firewall exposure ignored Google's
rule-priority and deny-wins semantics.

**Test-harness issues** (not AIPS bugs), recorded for transparency:
* Run 2 of the suite showed L2 failing. A fresh AIPS instance with a 90-second start-up lookback correctly
  re-detected the *previous test's* staged misuse. Shortening the lookback to 10 seconds isolated the tests,
  and the clean run passed 6/6.
* An earlier rerun collided on reused test account names.

## Known gaps (honest limits)

* **Undoing the attacker's actions.** AIPS stopped the attacker, but did not remove what the attacker had
  created (the rogue service accounts). That needs a follow-up capability: review, then revert the changes a
  frozen identity made.
* **Infrastructure half not tested live.** VM restart, MIG scaling, firewall containment and drift restore need a
  billed project. They pass end-to-end against the emulator only.
* **Small scale.** One project, one protected identity, one operator, and a short test window. Detection latency
  is bounded below by Google's audit-log delivery (seconds to tens of seconds) and by the 15–20 s AIPS cycle.
* **Human accounts.** A human Google account cannot be disabled through the IAM API. AIPS can freeze it
  internally and notify, but it cannot lock it out on the platform.

## Reproducing

The live suite drives `aips.config.build` plus `gcloud`. The procedure is in [GCP.md](GCP.md):
* a project without billing;
* a service account with `roles/iam.serviceAccountCreator`;
* the operator holding `roles/iam.serviceAccountTokenCreator` on it;
* AIPS configured with `[gcp]`, `adapter.type = "gcp"` and an identity boundary for the service account.

Only run this against a project you own.
