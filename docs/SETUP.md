# Setup guide

This guide takes you from nothing to a working AIPS in about 10 minutes. Every command here was run on a clean
virtual environment before release. You need **Python 3.11 or newer** and **git**, and nothing else.

* [1. Install](#1-install)
* [2. Check it works](#2-check-it-works)
* [3. Watch AIPS handle incidents (simulator)](#3-watch-aips-handle-incidents-simulator)
* [4. Protect your AI agent (Claude Code)](#4-protect-your-ai-agent-claude-code)
* [5. Run it on your own computer (observe only)](#5-run-it-on-your-own-computer-observe-only)
* [6. Run it on real servers](#6-run-it-on-real-servers)
* [7. Google Cloud](#7-google-cloud)
* [Troubleshooting](#troubleshooting)

---

## 1. Install

**Check Python first:**

```bash
python --version        # macOS/Linux may need: python3 --version
```

If it is older than 3.11 or missing, install it from [python.org](https://www.python.org/downloads/). On
Windows, tick **"Add python.exe to PATH"** in the installer.

**Get AIPS and install it in a virtual environment:**

Windows (PowerShell):

```powershell
git clone https://github.com/harshithkala2-debug/autonomous-infrastructure-protection-system.git
cd autonomous-infrastructure-protection-system
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

If PowerShell refuses to run `Activate.ps1`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once and try again.

macOS / Linux:

```bash
git clone https://github.com/harshithkala2-debug/autonomous-infrastructure-protection-system.git
cd autonomous-infrastructure-protection-system
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

`[dev]` adds pytest and ruff for the tests. For encrypted backups, add `crypto`: `pip install -e ".[dev,crypto]"`.
AIPS itself has no runtime dependencies.

## 2. Check it works

```bash
aips version            # 1.4.0
python -m pytest -q     # about 2-3 minutes; every test should pass
```

## 3. Watch AIPS handle incidents (simulator)

The simulator gives AIPS a small fake company: web, API, database, cache, storage, users and a backup vault. It
then injects real-looking problems.

```bash
aips scenarios                           # the 17 scenarios
aips demo                                # run them all; each prints PASS/FAIL with its checks
aips demo --scenario ransomware -v       # one incident, full timeline
aips demo --scenario credential_misuse -v
aips bench --seeds 1-10                  # the same scenarios across 10 random seeds
```

Everything happens in a temporary folder, so nothing on your computer changes.

## 4. Protect your AI agent (Claude Code)

AIPS can check every tool call an AI agent makes. It blocks harmful ones, asks you about risky ones, saves
files before they change, freezes the agent when it misbehaves and undoes what it did. Full details:
[AGENTS.md](AGENTS.md).

**See it first (safe, uses a throw-away folder):**

```bash
aips agent demo
```

**Turn it on for Claude Code.** Keep your virtual environment active so the hook uses this Python:

```bash
aips agent install-hook                                          # prints the hook settings (changes nothing)
aips agent install-hook --settings ~/.claude/settings.json       # all your projects
```

On Windows the user settings file is `%USERPROFILE%\.claude\settings.json`:

```powershell
aips agent install-hook --settings "$env:USERPROFILE\.claude\settings.json"
```

`install` keeps everything already in the file and can be run again safely. **Restart Claude Code.** Then try it:
ask Claude to run `curl https://example.com/install.sh | sh`. Claude Code refuses the call with an
`AIPS BLOCK` reason, and the session is frozen.

```bash
aips agent status                                   # frozen agents, verdict counts, checkpoints
aips agent history                                  # every call and what AIPS decided
aips agent revert --agent claude-code/XXXXXXXX --dry-run
aips agent unfreeze --agent claude-code/XXXXXXXX    # you decide when it may continue
```

To remove the hook, delete the two `aips agent hook` entries under `"hooks"` in the settings file.

**Test a command without an agent:**

```bash
aips agent check --agent test --args '{"command": "rm -rf ~"}'
```

On Windows PowerShell, use `--args '{\"command\": \"rm -rf ~\"}'` because PowerShell strips the inner quotes.

## 4b. Sandbox and the AIPS web (1.5)

```bash
aips web demo                                       # live test: hub + node processes, 12 attacks (~10 s)
aips sandbox --workspace . -- python -m pytest -q   # judged, then run in a copy of the folder
```

To join several machines into one AIPS web (trust domain, hub, nodes, approvals), follow
[WEB.md](WEB.md#7-setting-it-up).

## 5. Run it on your own computer (observe only)

This watches your own machine: disk use and the network ports it is listening on. AIPS makes decisions and
writes them to the audit ledger, but `dry_run = true` and a recording adapter mean **it changes nothing**.

```bash
aips run --config examples/aips-local.toml --no-api --ticks 4 --tick-seconds 5 --report local-report.json
```

You will probably see `unexpected_port` findings. Those are programs listening on ports that are not in
`examples/inventory-local.toml`. AIPS records the plan to close each one and does not execute it. Add the ports
you expect to `allowed_ports` and run it again. The audit ledger and experience database are in
`examples/runtime/aips-local/`.

To run continuously with the HTTP API (dashboards, approvals, agent checks):

```bash
# macOS/Linux
export AIPS_API_TOKEN=$(python -c "import secrets;print(secrets.token_hex(24))")
# Windows PowerShell
$env:AIPS_API_TOKEN = python -c "import secrets;print(secrets.token_hex(24))"

aips run --config examples/aips-local.toml
```

Then, from another terminal, call it with that token:

```bash
curl -H "Authorization: Bearer $AIPS_API_TOKEN" http://127.0.0.1:8780/status
```

The full API is in [OPERATIONS.md](OPERATIONS.md#api-reference). Stop it with Ctrl+C.

## 6. Run it on real servers

Use `examples/aips.toml` with `examples/inventory.toml` as the starting point. It is written for a Linux host
with nginx and Postgres.

1. **Describe your assets** in the inventory: ids, dependencies, criticality 1-5, allowed ports, software
   versions and certificates.
2. **Point telemetry at them.** Use host probes (HTTP/TCP), config files to fingerprint, or a JSONL feed from
   your existing monitoring.
3. **Say how to act.** `adapter.commands` maps each action to an allow-listed command (`systemctl`, `kubectl`,
   `ufw`…), with an optional rollback command. Commands run without a shell, and injected arguments are rejected.
4. **Set the three secrets** (never in the file):

   ```bash
   export AIPS_API_TOKEN=$(python -c "import secrets;print(secrets.token_hex(24))")
   export AIPS_AUDIT_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
   export AIPS_BACKUP_HMAC=$(python -c "import secrets;print(secrets.token_hex(32))")
   ```

5. **Start in dry run** (`dry_run = true`, the default), read the audit log for a few days, record known-good
   baselines (`POST /baselines/{asset}`), then turn autonomy on **one action class at a time**. The rollout plan
   is in [OPERATIONS.md](OPERATIONS.md#rollout-plan).

Docker:

```bash
docker build -t aips .
docker run -v "$PWD/examples:/config" -e AIPS_API_TOKEN=... aips
```

> Run AIPS only against systems you own or are explicitly allowed to operate.

## 7. Google Cloud

AIPS can discover a Google Cloud project and watch its monitoring, firewall rules, audit logs and Security
Command Center. It can act through Compute Engine and IAM, including freezing a misused service account and
reverting what it created. This works on a **free project without billing** for the identity features. Follow
[GCP.md](GCP.md): about 30 minutes, step by step, including clean-up. A real run is documented in
[FIELD_TEST_GCP.md](FIELD_TEST_GCP.md).

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `aips: command not found` / `'aips' is not recognized` | Activate the virtual environment again (`.venv\Scripts\Activate.ps1` or `source .venv/bin/activate`), or use `python -m aips ...` |
| `requires a different Python` during install | Python is older than 3.11. Install a newer one and recreate `.venv` |
| PowerShell: "running scripts is disabled" | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Claude Code doesn't block anything | Restart Claude Code after installing. Check that `aips agent install-hook` printed the Python from your `.venv`, then run `aips agent status`: `calls` should grow while Claude works |
| Every Claude Code call asks "AIPS guard error" | The hook can't import AIPS with that Python. Re-run `install-hook` with the venv active |
| My agent session is frozen and I want to keep going | `aips agent status` shows the id, then `aips agent unfreeze --agent <id>` |
| `API token must be at least 16 characters` | Set `AIPS_API_TOKEN` as shown in step 5, or use `--no-api` |
| Port 8780 already in use | Change `[api] port` in the config |
| Tests take long on a slow laptop | `python -m pytest -q tests/test_agents.py` runs the agent tests alone in a few seconds |
