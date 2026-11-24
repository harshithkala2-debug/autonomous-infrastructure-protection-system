# Threat model

AIPS holds privileged access, so it is itself a high-value target. This document lists what it defends against,
how, and what it does not cover.

## Assets

1. The infrastructure AIPS can change, through adapter credentials.
2. The backup vault.
3. The audit ledger, which is the record of truth for every automated change.
4. Identity boundaries and profiles.
5. The control-plane API, through which approvals, appeals and the kill switch are operated.

## Threats and mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | **Poisoned telemetry** makes AIPS take harmful actions | Actions are limited to a fixed catalogue with risk tiers. Approval is required above the autonomy ceiling, and rate limits plus a global budget apply. Command arguments are validated against a strict allow-list character set, and no shell is used. |
| T2 | **Argument / command injection** through findings, tags or asset IDs | `CommandAdapter.render` rejects any value outside `[A-Za-z0-9_.:@/=+,-]` and uses argv execution only. |
| T3 | **Repair loop** (restart storm) | Per-target rate limit (6 per hour) followed by mandatory approval. Attempts are bounded, and the incident fails to humans with rollback. |
| T4 | **Attacker trains the behaviour profile** | Only allowed, low-risk, successful events are learned. Boundary violations are denied whatever the profile says. |
| T5 | **Attacker freezes legitimate users** (denial of service through AIPS) | Unusual-but-permitted activity is never frozen on a single event. Protected identities need approval. Appeals are reviewed by a different person, and a granted appeal teaches the system (false-positive memory). |
| T6 | **Ransomware encrypts the backups** | The vault is write-once with a retention lock and an IP-gated API. Suspect snapshots are never replicated. Restore needs two approvers and verifies hashes. |
| T7 | **Tampering with backup content or manifests** | SHA-256 is re-checked on every read, manifests carry an HMAC signature, and scrubs run on a schedule. |
| T8 | **Tampering with the audit trail** | The HMAC hash chain detects modification, deletion and reordering. Ship the ledger to WORM storage or a SIEM. |
| T9 | **Compromised known-good baseline** | Baselines are captured only through an explicit, audited call with an approver identity, never implicitly. |
| T10 | **Malicious intelligence feed** | HTTPS only, size caps, XML entity declarations rejected, source reliability weighting. A finding requires a local environment check, and upgrades always need approval. |
| T11 | **Unauthorised API use** | Bearer token (constant-time compare, minimum 16 characters), default bind 127.0.0.1, 1 MB body cap. Human identities are recorded in the audit log. |
| T12 | **Disclosure of the organisation's network ranges** | Vault allow-lists live only in private configuration. Logs contain salted hashes of caller IPs. |
| T14 | **An AI agent is wrong, loops or is hijacked by prompt injection** | Every tool call is judged before it runs (harm rules, policy, behaviour). Critical actions are blocked and the agent frozen. Files are checkpointed first and reverted from the first suspicious call. Injected instructions in tool output taint the session, so a human approves risky calls. See [AGENTS.md](AGENTS.md). |
| T15 | **The agent attacks its own guard** (unfreeze itself, edit hook settings, touch the guard's state) | Self-protection rules block these as critical. Only a human can unfreeze. The hook fails to *ask*, never to allow. Residual risk: the guard is not a sandbox, so a deliberately obfuscated command can evade text rules. Use OS isolation for untrusted agents. |
| T16 | **An outsider or stolen machine joins the AIPS web**, or replays captured traffic | Closed trust domain: issued per-node keys, signed requests and responses, nonce replay cache, 30 s clock window, revocation by epoch, roles per node. Rejections become findings. See [WEB.md](WEB.md). |
| T17 | **An AI agent fakes a human approval** or covers its tracks | The passphrase is never stored (PBKDF2 verifier only), approvals are bound to the exact action, expire and work once, and approvals are accepted on the hub machine only. `web_tamper` blocks agents touching keys and logs, and the audit ledger is hash-chained. |
| T18 | **A compromised node lies** (fake job results, bad replicas) | Results are accepted only from the node holding the lease, and replicas only if their hash matches. A liar is quarantined and revoked. |
| T19 | **An agent command escapes its sandbox** | A jail copy, stripped environment and limits. Windows low integrity stops writes outside the jail. Risky work goes to a disposable remote node. Residual risk: no filesystem confinement on Linux/macOS and best-effort network blocking without `unshare`. |
| T13 | **AIPS itself misbehaves** | Kill switch, dry-run mode and the two-person rule for HIGH risk. Containment is never auto-reverted, and every step is audited. |

## Out of scope / residual risk

* **Compromise of the AIPS web hub.** It holds the domain secret and can derive every node key. Run it on a
  hardened machine or account, keep agents off it and back up `domain.json` offline.

* **Compromise of the host running AIPS.** An attacker with root on that host can use the adapter credentials
  directly. Run AIPS on a hardened, dedicated host or account with least-privilege adapter credentials.
* **An HMAC key stolen together with write access to the ledger.** Keep the key in a secrets manager and ship
  the ledger off-host.
* **Sophisticated low-and-slow attacks** that stay below statistical detection.
* **Supply-chain attacks on the Python runtime.** The core has no third-party dependencies, which reduces the
  attack surface.

## Authorised use

AIPS is a defensive system. Test it only on infrastructure you own or have explicit written permission to test.
