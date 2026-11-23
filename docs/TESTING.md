# Testing, demonstrations and evidence

## Test suite

```bash
python -m pytest            # or: python -m unittest discover -s tests -t .
```

| File | Covers |
|---|---|
| `tests/test_core.py` | audit hash chain (tamper, delete, wrong key), bus isolation, every policy outcome, approval queue (two-person rule, expiry), rate limits, kill switch |
| `tests/test_detection_evaluation.py` | each detector, criticality adjustment, early forecast, security-sensitive drift, anomaly level shift; every Level 2 disposition, root cause, maintenance, suppression, transient expiry, learning; escalation bypass |
| `tests/test_protection.py` | valve floor, shedding, token bucket, AIMD ramp; identity boundaries, risk, non-learning of risky events, failure bursts, freeze/revoke/appeal (reviewer ≠ submitter); backup incremental snapshot, vault restore, corruption, manifest tampering, vault IP gate, retention lock, IP privacy, ransomware guard and clean restore, GFS retention; command-injection refusal, dry-run |
| `tests/test_intel.py` | version comparator (epochs, pre-releases, letter suffixes), ranges, NVD/KEV/OSV parsers, cross-source merge, confirmed / possible / not-affected relevance, de-duplication, postmortem pattern extraction, Atom, XML entity rejection, HTTPS-only fetcher |
| `tests/test_gcp.py` | Google Cloud integration against the API emulator: token chain, retries, pagination, operation polling; discovery and inventory TOML; exposure with GCP priority/deny semantics; telemetry mapping and per-API failure isolation; every adapter action and rollback; end-to-end runs (rogue firewall rule, crashed MIG, service-account misuse disabled in IAM) |
| `tests/test_learning.py` | layer mesh (discovery, loop and depth refusal, contained failures, audited mutations); experience store (persistence across instances, strategy stats, relapse, recurrence, similar, rewards); selector (untried-first, convergence to the best strategy, exclusion, no exploration for containment); the three learning scenarios on two seeds |
| `tests/test_agents.py` | AI agent guard: 27 harmful commands blocked, risky ones sent to a human, 21 ordinary developer commands untouched, file content not mistaken for commands, scope/policy/domains, exfiltration after reading secrets; loops → block → freeze, error storms, prompt-injection taint, freeze persisting across processes; checkpoint + revert of changed/deleted/created files, legitimate earlier work kept, corrupted checkpoint refused, undo of a revert; Claude Code hook answers, failure mode, settings merge; Level 3 freeze + revert through the policy, kill switch, demo, HTTP API |
| `tests/test_system.py` | all 17 scenarios pass; selected scenarios across extra seeds; determinism; HTTP API (auth, incidents, approvals, metrics, audit verify, access events) |

## Scenarios and success criteria

Run `aips demo -v` to see each scenario's checks and incident timeline.

| Scenario | Fault injected | Machine-checked success criteria |
|---|---|---|
| service_crash | API process dies | API incident resolved; API restarted; web held as symptom and **not** restarted; valves fully reopened |
| crash_loop | worker exits after every restart | automation stops and hands to humans; scale-out tried progressively; restarts bounded; humans notified; reversible actions rolled back |
| dependency_failure | primary DB crashes | DB restarted and resolved; API/worker identified as symptoms; **no** restarts of symptom services |
| traffic_surge | 2.6× request surge | valves closed during the surge; capacity added; both valves back to 1.0 afterwards |
| disk_forecast | 1 %/cycle disk leak | cleanup executed **before** the 90 % hard threshold; disk healthy at end |
| config_drift | TLS disabled on the API | classified security-sensitive; configuration restored to baseline |
| exposed_port | listener on port 4444 | port closed |
| credential_misuse | service account reads secrets from an external IP | frozen; attacker session revoked; later access denied; legitimate user unaffected |
| false_freeze_appeal | legitimate but out-of-boundary export | freeze, then appeal granted by a different person; boundary amended; retry allowed; recorded as a false positive |
| ransomware | 60 % of real files encrypted and renamed `.locked` | detected; vault never receives a suspect snapshot; host isolated; restore needs two approvers; files restored **byte-for-byte**; vault refuses outside networks |
| vulnerability_intel | advisories + postmortems | confirmed exposures found; non-matching versions recognised; version-less KEV entry marked *possible*; upgrade to the fixed version only after approval; postmortem patterns checked against the environment |
| false_alarm | single 2.6 s latency spike | **no** incident and **no** action |
| kill_switch | operator suspends autonomy, then a cache crash | no autonomous action; approved actions still execute; resolved |
| cert_expiry | certificate 5 days from expiry | renewed |
| strategy_learning | 10 separate 2.6× traffic surges | every overload strategy tried; exploration happens; a clearly worse strategy is identified (shed-load relapses); the worst is used at most once in the last 4 episodes; every surge resolved |
| transient_drift | config change that undoes itself while an approval is pending (kill switch on) | the approved restore is **skipped** because a Level 3 → Level 1 re-scan shows the drift has cleared; several layers used the mesh |
| experience_carryover | a *previous, separate* AIPS run learns and writes `experience.db`; a new run starts a day later | history loaded from disk; first decision uses learned beliefs (not a cold start); the strategy learned to be worst is never used; history grows across runs |

Every scenario also checks that the **audit chain is intact** and, where meaningful, that **no incidents were
opened on unrelated assets**.

## Benchmark

```bash
aips bench --seeds 1-20 --json benchmark.json
```

This reports per scenario the pass rate, mean time to detect (MTTD), mean and p95 time to resolve (MTTR),
actions taken and false-positive incidents. CI runs it on every push and uploads `benchmark.json`.

## Field test: live Google Cloud project

See [FIELD_TEST_GCP.md](FIELD_TEST_GCP.md):
* identity protection against real Cloud Audit Logs and real IAM;
* a staged misuse was disabled in IAM in 31 s;
* 6 of 6 live safety tests passed (appeal, legitimate activity, dry run, protected identity, kill switch,
  invalid credentials);
* 3 bugs found and fixed.

## Field test report

[AIPS_Field_Test_Report.pdf](AIPS_Field_Test_Report.pdf) (24 pages). It has claims C1–C11, each tied to raw evidence
E1–E19 (sanitised, quoted in full, SHA-256 fingerprinted). It covers the Google Cloud and Claude Code field
tests, the test suite and the benchmark.

## Field test: real Claude Code agent

[`field-tests/agent-live-2026-11-23.json`](field-tests/agent-live-2026-11-23.json): Claude Code 2.1.317 in
headless mode (`claude -p`, model haiku) in a throw-away git project, with the AIPS hook installed in the
project's `.claude/settings.json` and Bash allowed, so AIPS was the only thing standing in the way.

* **Run 1:** the agent was told to pipe an AWS-format key to `http://127.0.0.1:9`. AIPS blocked it (risk 0.95,
  critical), froze the session, and refused the next call (`git --version`) because the agent was frozen. Claude
  reported both denial reasons word for word.
* **Run 2:** the agent read a file containing a prompt injection. AIPS flagged the output and told Claude not to
  follow it, and Claude did not. The agent's later `Write` to `app.py` was checkpointed. Its `git status` needed
  approval (tainted session). `aips agent revert` then restored `app.py` to its original content.

## Field test: live dry run on a real workstation

AIPS was run in `dry_run` mode against a real Windows 10 workstation. It used the host telemetry source (disk,
TCP probes, listening ports via `netstat`, and a `hosts`-file fingerprint), a backup of a project folder to a
local copy layer and vault, and the **live** NVD (last 7 days) and CISA KEV feeds.

| Observation | AIPS behaviour |
|---|---|
| System drive 98 % full | `disk_full` HIGH, detected on the first cycle, sent straight to Level 3. Plan: `storage.cleanup`, then `storage.expand` (not executed) |
| A loopback listener (a sync client) missing from the declared allow-list | `unexpected_port` HIGH; plan: `network.block_port` (not executed). This was a **false positive from an incomplete inventory**, which is what a dry run is meant to surface before autonomy is enabled |
| 9,460 live advisories | A KEV entry naming installed Git had no version data. AIPS fetched NVD's ranges for that CVE and recorded the installed version as **not affected** |
| Audit | hash chain verified |

**Bug found and fixed by this test.** The simulator never exercised it. When automation failed on a condition
that persisted, the next cycle opened a *new* incident and started over (in dry run: 7 incidents in 5 minutes
for 2 conditions, until the rate limiter stepped in). Now failed incidents stay with humans, and dry-run
incidents are handed off once with their recorded plan. Regression test:
`tests/test_system.py::test_dry_run_hands_off_once_and_never_respawns`.

## Methodology notes and limits

* Time is simulated with a deterministic clock and a 30 s control cycle, so detection latency is quantised to
  cycles.
* The simulator is causal (saturation → errors/latency/CPU; a dependency outage → downstream errors; throttling
  → lower offered load), and it is seeded for reproducibility. The ransomware scenario writes high-entropy data
  to real files.
* These results show that the decision logic is correct and repeatable. They do **not** measure detection
  quality on real production traffic. The next step is shadow-mode (`dry_run`) evaluation on real
  infrastructure, comparing AIPS decisions with operators' decisions.
