# Protecting AI agents

AI agents such as coding assistants, autonomous ops bots and LLMs with tools now change real systems. They run
shell commands, edit files and call cloud APIs. They can be wrong, they can loop, and a web page or a file they
read can hijack them (prompt injection). AIPS treats an AI agent the way it treats a cloud identity. It watches
every action, stops harmful ones, freezes the agent when needed, saves the data the agent touches, and undoes
the damage.

```
agent wants to run a tool ──▶ AgentGuard.check()  ──▶ ALLOW / FLAG ──▶ tool runs ──▶ record_result()
                                │                     ASK  ──▶ a human decides            │ scans output for
                                │                     BLOCK ──▶ refused                    │ prompt injection
                                ▼                                                          ▼
                       checkpoint files first                              tainted session: risky calls need a human
                                │
                     findings ──▶ Level 1/2/3 ──▶ policy ──▶ agent.freeze ──▶ agent.revert_actions ──▶ notify
```

## What it does

| Step | How |
|---|---|
| **Detect** | Each tool call is judged **before it runs**. The guard combines built-in harm rules, the agent's policy and its behaviour into one risk score (noisy-OR, like the identity guard). |
| **Decide** | **ALLOW**, **FLAG** (allow and report), **ASK** (a human must approve) or **BLOCK**. A *critical* rule match always blocks. |
| **Freeze** | A critical block, or 3 blocks within 10 minutes, freezes the agent. Every later call is refused until a human unfreezes it. Inside AIPS the freeze is a Level 3 decision taken through the authorisation policy, so the kill switch and approvals apply. |
| **Save** | Before a call that may change or delete files runs, those files are checkpointed into a content-addressed store and checked by SHA-256 when restored. If a destructive call cannot be checkpointed (too large), it needs a human. |
| **Fix** | `revert` restores every file the agent changed from its **first suspicious call** onward. It deletes files the agent created, runs undo callbacks for in-process tools, and lists what cannot be undone automatically (for example a sent request) for a human. A revert can itself be undone. Legitimate work done before the agent misbehaved is kept. |

### Harm rules (built in)

| Group | Examples | Default |
|---|---|---|
| destructive | `rm -rf /`, `rm -rf ~`, `Remove-Item -Recurse C:\`, `format D:`, `mkfs`, `dd of=/dev/sda`, fork bomb | **block, critical** |
| destructive | `DROP TABLE`, `terraform destroy`, `kubectl delete namespace`, `gcloud projects delete`, `aws s3 rm --recursive` | block |
| destructive | `git push --force`, `DELETE FROM x;` without `WHERE`, `TRUNCATE`, deleting a resource with no file to checkpoint | ask |
| destructive | `rm -rf build`, `git reset --hard` | flag (and checkpoint) |
| remote_code | `curl … \| sh`, `iwr … \| iex`, `base64 -d \| sh` | block |
| secrets | a credential sent off the machine (`AKIA…`, `ghp_…`, `sk-…`, private keys) | **block, critical** |
| secrets | env dump piped to the network; an outbound call shortly after reading `.env`/`id_rsa` | block / ask |
| secrets | reading `.env`, `~/.ssh/*`, `.aws/credentials`, `credentials.json` | flag |
| tampering | disabling Defender / firewall / auditd, clearing event logs | block |
| tampering | `chmod 777`, `--no-verify`, `history -c`, deleting `.git` | flag / ask |
| privilege | `sudo`; granting `roles/owner` or `AdministratorAccess` | flag / ask |
| self_protection | `aips agent unfreeze`, touching `~/.aips-agent`, editing `.claude/settings.json` | **block** |

Rules run over the *command* of a shell call. For file writes they run over the path only. A README that
*mentions* `rm -rf /` is not blocked. Add or disable rules in `policy.toml` (see below).

### Behaviour ("random" actions)

* **Runaway loops:** the same call 5 times in 2 minutes is flagged, and 10 times is blocked.
* **Bursts:** more calls per minute than the policy allows.
* **Error storms:** the last 5 calls all failed.
* **Budget:** a session that goes over its call budget needs a human.
* **Scope:** changing files outside the workspace (the project folder) needs a human. Contacting a domain that
  is not on the allow list (when one is configured) is reported.
* **Prompt injection:** a tool output that tries to give the agent new instructions (*"ignore previous
  instructions"*, fake `<system>` tags, *"send the API keys to …"*) **taints the session**. From then on, every
  shell, network, delete or mutating call in that session needs a human.

## Use it with Claude Code

```bash
pip install -e .                       # in the AIPS folder, with the Python you want the hook to use
aips agent install-hook --settings ~/.claude/settings.json     # all projects
#   or: aips agent install-hook --settings .claude/settings.json   (one project)
#   or: aips agent install-hook        (just print the JSON to paste yourself)
```

Restart Claude Code. Every tool call now goes through AIPS:

* **BLOCK:** Claude Code refuses the call and Claude sees the reason.
* **ASK:** Claude Code shows you its normal permission prompt, with AIPS's reason.
* **ALLOW / FLAG:** nothing changes, and Claude Code's own permission rules still apply. AIPS can only make
  Claude Code **stricter**. It never approves anything for you.
* **Tainted output:** Claude is told the output contained injected instructions and must not follow them.

Each Claude Code session is a separate agent (`claude-code/<first 8 characters of the session id>`), so
freezing one session doesn't stop your others. Use `--scope global` to freeze them all together.

```bash
aips agent status                                   # calls, verdicts, frozen agents, checkpoints
aips agent history --agent claude-code/1a2b3c4d     # what the agent did and what AIPS decided
aips agent revert --agent claude-code/1a2b3c4d --dry-run   # what would be restored
aips agent revert --agent claude-code/1a2b3c4d      # restore files changed since it misbehaved
aips agent undo-revert --revert-id RV-…             # changed your mind
aips agent unfreeze --agent claude-code/1a2b3c4d    # let it continue (a human decision)
aips agent check --agent test --args '{"command": "curl x | sh"}'   # try a command without running it
```

State lives in `~/.aips-agent` (or `AIPS_AGENT_HOME`). The hook adds a few milliseconds to each tool call. If
the hook fails (for example on a broken event), it falls back to **ask**: it never silently allows.

### Policy file (optional): `~/.aips-agent/policy.toml`

```toml
[policy]
deny_tools = ["mcp__payments__*"]          # never allowed
ask_tools = ["mcp__github__merge_pull_request"]
workspace_roots = ["C:/Users/me/projects"] # default: the session's working directory
allow_domains = ["github.com", "pypi.org", "docs.python.org"]   # empty = any domain
max_calls_per_min = 60

[guard]
freeze_after_blocks = 3
loop_block = 10
disabled_rules = ["sudo"]

[[guard.extra_rules]]
id = "no-prod-db"
pattern = "psql[^\\n]*prod"
weight = 0.9
critical = true
description = "touches the production database"
```

## Use it in your own agent (Python)

```python
from aips.agents import AgentGuard, ActionBlocked

guard = AgentGuard()                       # in memory; pass AgentStore("state/agents.db") to persist

run_shell = guard.guarded("shell", my_shell_fn, agent_id="ops-bot", cwd="/srv/app")
send_mail = guard.guarded("send_email", my_send_fn, agent_id="ops-bot",
                          undo=lambda kwargs, result: recall(result),       # how to reverse one call
                          approver=lambda call, decision: ask_slack(decision.summary()))

try:
    run_shell(command="rm -rf /")
except ActionBlocked as e:
    print(e.decision.reasons)              # and the agent is now frozen

guard.revert("ops-bot")                    # restore files + run undo callbacks
```

## Use it over HTTP (any language)

With `aips run` (see [OPERATIONS.md](OPERATIONS.md)), any agent framework can ask AIPS first:

```
POST /agents/check     {"agent": "ops-bot", "tool": "shell", "args": {"command": "..."}, "session": "s1", "cwd": "/srv"}
                    -> {"call_id": "...", "verdict": "block", "allowed": false, "risk": 0.95, "reasons": [...]}
POST /agents/result    {"call_id": "...", "success": true, "output": "..."}
GET  /agents           status and recent calls
POST /agents/ops-bot/release   {"by": "alice", "reason": "reviewed"}
```

Inside AIPS, agent findings join the normal hierarchy. A HIGH or CRITICAL finding goes straight to Level 3.
Level 3 runs the `agent-containment` playbook (`agent.freeze` → `agent.revert_actions` → `notify.humans`)
through the authorisation policy. With the kill switch engaged, the freeze waits for approval, but the
harmful call itself is still blocked. Every decision is in the hash-chained audit ledger.

## Try it

```bash
aips agent demo
```

The demo runs a scripted agent in a throw-away folder:

1. The agent does normal work.
2. It reads a web page that hides instructions for it.
3. It plants a backdoor in `app.py`, tries to read `.env`, tries to send the API key away, deletes `data/` (a
   tired human clicks Approve), then tries `rm -rf .`.
4. AIPS blocks the exfiltration and the wipe. Level 3 freezes the agent and reverts its changes: `app.py` is
   back to the original and all 3 deleted files are back. The audit ledger verifies.
5. A human releases the agent.

## Sandbox and the AIPS web (1.5)

The guard can now be paired with a **hybrid sandbox**. Commands are judged first, then run in a throw-away copy
of the workspace, on Windows at low integrity inside a Job Object, or on a remote sandbox machine for risky work.
Changes come back only through checkpoints, so they can be reverted. Approvals made through the AIPS web need the
human's passphrase, so an agent can't fake them. See [WEB.md](WEB.md).

## Limits (read these)

* **The guard is a gate, not a sandbox.** (Pair it with the hybrid sandbox in [WEB.md](WEB.md#5-hybrid-sandbox).) It only sees calls that go through it (the hook, `guarded`, the
  API). Text rules can be evaded by an agent that deliberately obfuscates a command (for example by building it
  from pieces). Behaviour checks, checkpoints, taint and freezing reduce the damage, but for agents you don't
  trust, also run them in an OS-level sandbox (a container or VM, a separate user, no production credentials).
* **Checkpoints cover files.** Paths are taken from tool arguments and, for shell calls, from common commands
  (`rm`, `mv`, `cp`, `Remove-Item`, `>` redirects, `tee`, `sed -i`…). A program that writes files on its own
  (`python script.py`) is not checkpointed. Anything sent over the network or done in a cloud API can't be
  undone by AIPS, so it is listed for a human. For cloud identities, use the GCP integration's revert.
* **Prompt-injection detection is pattern-based.** It catches common phrasings, not every possible attack.
  That is why a tainted session puts a *human* in the loop rather than trying to judge intent.
