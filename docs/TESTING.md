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
| `tests/test_system.py` | all 14 scenarios pass; selected scenarios across extra seeds; determinism; HTTP API (auth, incidents, approvals, metrics, audit verify, access events) |

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

Every scenario also checks that the **audit chain is intact** and, where meaningful, that **no incidents were
opened on unrelated assets**.

## Benchmark

```bash
aips bench --seeds 1-20 --json benchmark.json
```

This reports per scenario the pass rate, mean time to detect (MTTD), mean and p95 time to resolve (MTTR),
actions taken and false-positive incidents. CI runs it on every push and uploads `benchmark.json`.

## Methodology notes and limits

* Time is simulated with a deterministic clock and a 30 s control cycle, so detection latency is quantised to
  cycles.
* The simulator is causal (saturation → errors/latency/CPU; a dependency outage → downstream errors; throttling
  → lower offered load), and it is seeded for reproducibility. The ransomware scenario writes high-entropy data
  to real files.
* These results show that the decision logic is correct and repeatable. They do **not** measure detection
  quality on real production traffic. The next step is shadow-mode (`dry_run`) evaluation on real
  infrastructure, comparing AIPS decisions with operators' decisions.
