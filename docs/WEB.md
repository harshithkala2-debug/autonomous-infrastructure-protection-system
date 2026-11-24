# The AIPS web, hybrid sandbox and machine learning (1.5.0)

The AIPS web joins every protected machine into one **closed trust domain** run by one **orchestrator** (the
hub). Machines can be laptops, servers or cloud VMs; they all connect *out* to the hub, so a node behind NAT or
in a cloud network needs no open ports.

```
                         ┌──────────── trust domain "home-web" ────────────┐
   human ── passphrase ─►│  HUB (orchestrator)                             │
   (approvals only)      │   • verifies every signed request, signs replies │
                         │   • node registry + telemetry ML (Isolation Forest)
                         │   • job routing with leases and failover        │
                         │   • protected storage + replication + repair    │
                         │   • tamper-evident audit log → AIPS findings    │
                         └──▲───────────▲──────────────▲───────────────▲───┘
                  signed    │           │              │               │
              ┌─────────────┴┐  ┌───────┴──────┐  ┌────┴─────────┐  ┌──┴──────────┐
              │ laptop       │  │ box-1        │  │ store-a      │  │ cloud-vm    │
              │ role: client │  │ role: sandbox│  │ role: storage│  │ sandbox     │
              │ (agent host) │  │ runs jobs    │  │ keeps copies │  │ (disposable)│
              └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘
```

## 1. Closed trust domain

`aips web init` creates one 256-bit domain secret on the hub. `aips web issue NODE --roles ...` gives a node a
credential that holds **only its own key**, derived from the secret, the node name and an *epoch*.

* Every request carries a signed envelope: domain, node, epoch, timestamp, nonce, method, path and the SHA-256 of
  the body (HMAC-SHA256).
* The hub rejects:
  * other domains and unknown nodes;
  * wrong keys and tampered bodies or paths;
  * replays (same nonce) and requests outside a 30-second clock window;
  * revoked nodes and old credentials.
* Every response is signed back and bound to the request's nonce. A node can tell the real hub from an impostor,
  and a response can't be replayed as a request.
* Revoking or re-issuing a node bumps its epoch, so its old key stops working everywhere at once.
* Roles limit what a node may do:
  * `client` can store, fetch, run sandbox jobs and ask for approvals;
  * `sandbox` runs jobs;
  * `storage` keeps replicas;
  * `observer` only reads status.
* Rejected requests become `web_intrusion` findings.

Only standard-library HMAC-SHA256 is used, with no home-made cryptography. The envelope gives *authentication*.
For *encryption* on a real network, run the hub with TLS (`--tls-cert/--tls-key`) or behind a TLS proxy.

## 2. Human-only approvals an agent can't fake

The human's passphrase is **never stored**. Only a salted PBKDF2 verifier is on disk (240,000 iterations), so an
agent that reads every file on the machine still can't make an approval. When the human unlocks the hub, the
derived key exists only in the hub's memory.

* An approval is an HMAC over (request id, SHA-256 of the exact action, expiry).
  * Changing one character of the action invalidates it.
  * It expires after 10 minutes and works once.
* The real human is never locked out: a wrong passphrase costs a back-off capped at 30 seconds, never a lockout.
  A one-time recovery code, shown once at setup, resets a forgotten passphrase.
* Approvals are accepted only on the hub machine. A fake one becomes a `web_fake_approval` finding.
* New harm rule `web_tamper` (critical). An AI agent is blocked from reading or changing `.aips-web`,
  `domain.json`, `human.json` or credential files, from editing the web audit log, and from running
  `aips web approve|unlock|revoke|issue|reset-passphrase`.

## 3. Protected storage

* Objects are content-addressed (SHA-256), compressed and written read-only (write once, read many). With the
  optional `cryptography` extra and a key, they're also encrypted with AES-256-GCM. Every read re-checks the hash.
* The name → version index is a hash-chained, HMAC-keyed ledger. Editing, reordering or deleting a line is
  detected, and writes stop until it's fixed.
* Nothing is overwritten. A delete appends a tombstone, and only after the retention lock has expired. Through
  the hub, a delete also needs a human approval.
* Every object is replicated to `replication` storage nodes (2 by default).
* A corrupted hub copy is **repaired from a replica** automatically (`storage_corruption` finding).
* A replica that returns wrong bytes is **quarantined**. A replica that honestly reports its copy is bad is not.

## 4. The orchestrator

* **Registry and telemetry.** Nodes send signed heartbeats with real CPU %, memory %, process count, running
  jobs and errors (Windows via the Win32 API, Linux via `/proc`).
* **Machine learning on telemetry.** An Isolation Forest scores each heartbeat against the history of all nodes.
  A value far outside anything ever seen on two or more metrics is flagged too, because Isolation Forest can't
  split a metric that never varied. These become `web_node_anomaly` findings.
* **Routing.** A sandbox job goes to the least-loaded sandbox node.
* **Leases and failover.** A job whose node goes silent past its lease moves to another node, never back to the
  silent one. It gives up after 3 attempts.
* **Quarantine.** A node that sends a result for a job it doesn't hold, or a replica with wrong content, is
  revoked at once (`web_node_quarantined`).
* **Audit.** Everything accepted, rejected and decided goes into a tamper-evident ledger (`web-audit.jsonl`).
* **AIPS integration.** `WebHub(on_finding=aips.ingest_findings)` sends every web finding through the normal
  Level 1 → 2 → 3 hierarchy.

## 5. Hybrid sandbox

Every command is first judged by the AgentGuard and the learned risk model. **Blocked commands never run.**
Everything else runs in a **jail**, a throw-away copy of the workspace, never the real folder. Changes reach the
real folder only through `promote`, which checkpoints each file first, so `aips agent revert` can undo them.

| Tier | Where | Isolation |
|---|---|---|
| **local** | this machine | jail copy; environment stripped of all inherited variables (no tokens or cloud keys); own TEMP/HOME; timeout; output cap; dead proxy for HTTP clients. **Windows:** low integrity (can't write the user's files outside the jail) + Job Object (memory cap, process cap, everything killed with the job). **Linux/macOS:** `setrlimit` caps, own session, and `unshare -rn` (no network) where unprivileged namespaces are allowed |
| **remote** | a `sandbox` node of the web (another machine or a cloud VM) | the same, on a machine you can throw away |

Risky but allowed work goes to the **remote** tier when a sandbox node is online:
* flagged or approved calls;
* network and install commands (`curl`, `pip install`, `git clone`…);
* a learned risk ≥ 0.5.

`SandboxResult.isolation` lists exactly which protections were active for each run.

```powershell
aips sandbox --workspace . -- python build.py           # judged, run in a copy, report changes
aips sandbox --workspace . --promote -- "echo x> a.txt"  # also copy the changes back (revertable)
aips sandbox --remote laptop.json -- pip install requests  # risky work goes to a sandbox node
```

## 6. Machine learning (standard library only)

* **`CommandRiskModel`** is online logistic regression over hashed words, word pairs and character 3-grams of a
  tool call.
  * It ships trained on a small labelled set.
  * It learns from human decisions (`AgentGuard.learn(call_id, harmful)`).
  * It explains a score by its top tokens.
  * In the guard it's **advisory**: at most +0.45 risk, never critical. The rules stay the authority.
  * On the 48 commands in `tests/test_agents.py`, which it wasn't trained on: 24 of 27 harmful commands score
    above 0.5 and 0 of 21 benign ones do. The 3 misses are `format D:`, `systemctl stop auditd` and
    `wevtutil cl Security`, all of which the rule engine blocks.
* **`IsolationForest`** (Liu, Ting and Zhou, 2008) is used for node telemetry.

## 7. Setting it up

```powershell
# on the hub machine
aips web init --domain home-web                 # asks for the human passphrase, prints a recovery code
aips web issue laptop  --roles client  --hub http://HUB:8443 --out laptop.json
aips web issue box-1   --roles sandbox --hub http://HUB:8443 --out box-1.json
aips web issue store-a --roles storage --hub http://HUB:8443 --out store-a.json
aips web hub --host 0.0.0.0 --port 8443 --tls-cert hub.crt --tls-key hub.key   # asks to unlock approvals

# on each node (copy its credential file there privately, then delete it on the hub)
aips web node --cred box-1.json --cafile hub-ca.crt

# anywhere with a client credential
aips web status --cred laptop.json

# on the hub machine, when something needs a human
aips web approvals --hub http://127.0.0.1:8443
aips web approve REQUEST_ID --hub http://127.0.0.1:8443
```

A cloud sandbox node is any small VM with Python 3.11+, `pip install` of this repository and its credential.
It only makes outbound connections to the hub.

## 8. Live test

`aips web demo` (and `tests/test_web.py::LiveDemoTest`) starts a real hub and real node **processes**, then
attacks them. Result on a Windows 10 laptop (2 cores, 3.7 GB RAM): **12/12**, about 10 s, stable over 4 runs.
Evidence: [`field-tests/web-live-2026-11-24.json`](field-tests/web-live-2026-11-24.json).

| # | Attempt | Outcome |
|---|---|---|
| W1 | three node processes join | all online |
| W2 | other domain with the same names, guessed key, byte-for-byte replay, revoked node | all rejected; `web_intrusion` |
| W3 | job on the sandbox node; write outside the jail; 900 MB memory bomb | runs; write **denied** (low integrity); bomb stopped (512 MB cap) |
| W4 | hub's copy of a backup overwritten ("ransomware") | repaired from a replica; `storage_corruption` |
| W5 | storage index edited | detected |
| W6 | node takes a job and goes silent | job moved to a healthy node and finished |
| W7 | node sends a fake "all clean" result | quarantined, its key revoked |
| W8 | approvals forged from the files on disk (verifier, domain secret, random) | all refused; the real passphrase works |
| W9 | AI agent reads the web's keys / approves for the human | blocked (`web_tamper`) |
| W10 | `curl … \| sh`; edit in the sandbox; promote; revert; `pip install` | blocked; real file untouched until promoted; revert restores it; install sent to the remote tier |
| W11 | node telemetry suddenly wrong | `web_node_anomaly` |
| W12 | audit log | verifies |

## 9. Limits (read these)

* **One machine.** The live test ran every node as a separate process on one laptop over loopback, not on
  separate physical machines or in a real cloud. The code is the same, but real networks add latency, NAT and TLS
  set-up that this test didn't exercise.
* **Star topology.** The hub is a single point of failure and the most valuable target. Run it on a hardened
  machine, back up `domain.json` offline, and keep agents off it. Hub high availability isn't built yet.
* **Linux/macOS sandbox** has no filesystem confinement outside the jail. Only Windows low integrity provides
  that. Run sandbox nodes as a separate user, in a container or on a disposable VM. Network blocking is real only
  with `unshare -rn`; elsewhere the dead proxy stops well-behaved HTTP clients, not raw sockets.
* **Same-user attacks on the hub's memory** (a debugger attached to the hub process) are out of scope. That's
  another reason to run the hub as its own user or machine.
* **ML is small and advisory.** The risk model was trained on about 80 examples and the telemetry model on what
  your nodes report. Both add evidence and never decide alone.
* **Symmetric keys.** The hub can derive every node key. A stolen `domain.json` means rebuilding the domain
  (`aips web init --force`, then re-issue every node).
