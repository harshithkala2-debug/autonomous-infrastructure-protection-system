# Operations guide

## Rollout plan

1. **Inventory.** Describe your assets in `inventory.toml`: dependencies, criticality, software versions,
   allowed ports, certificates and the attributes used by intel checks.
2. **Dry run (1–2 weeks).** Set `dry_run = true`. AIPS detects, evaluates and decides; every decision appears in
   the audit log and the API, and nothing is executed. Review false positives, tune thresholds, and add
   maintenance windows and suppressions.
3. **Notify-only autonomy.** Set `max_autonomous_risk = "LOW"` and enable only the `CommandAdapter` templates for
   restart, scale-out and throttle.
4. **Widen gradually.** Raise the ceiling to MEDIUM for drift restore, port blocking and identity freeze. Keep
   HIGH risk behind approvals with the two-person rule.
5. **Drills.** Schedule `aips backup drill` and review `aips bench` results after each upgrade.

## Baselines

Capture the known-good configuration explicitly after a reviewed change:

```bash
curl -X POST -H "Authorization: Bearer $AIPS_API_TOKEN" -d '{"approved_by":"alice"}' \
     http://127.0.0.1:8780/baselines/web
```

## API reference

All endpoints except `/health` require `Authorization: Bearer <token>`.

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/health` | | liveness |
| GET | `/status` | | overview: incidents, valves, identity, backup, audit, detectors |
| GET | `/metrics` | | Prometheus metrics |
| GET | `/incidents?status=open` | | list incidents |
| GET | `/incidents/{id}` | | full incident with timeline |
| POST | `/incidents/{id}/close` | `by, resolution, false_positive` | human close |
| GET | `/approvals` | | pending approvals |
| POST | `/approvals/{id}/approve` | `approver, note` | approve (HIGH risk needs two distinct approvers) |
| POST | `/approvals/{id}/reject` | `approver, note` | reject; a note starting with "false positive" teaches the system |
| GET | `/valves` | | valve positions and modes |
| POST | `/killswitch` | `engaged, by, reason` | suspend or resume autonomy |
| POST | `/access-events` | `identity_id, action, resource, source_ip, success, session_id` | evaluate an access event (returns allow/deny + risk) |
| POST | `/findings` | `asset, title, severity, category, signal, confidence, source` | inject an external alert |
| POST | `/appeals` | `identity_id, submitted_by, reason` | appeal a freeze |
| POST | `/appeals/{id}/review` | `reviewer, grant, note, allow_action, allow_resource` | decide an appeal; optionally amend the boundary |
| POST | `/baselines/{asset}` | `approved_by` | record current config as known-good |
| GET | `/mesh` | | layer capabilities, call statistics, recent inter-layer calls |
| POST | `/mesh/call` | `target, capability, payload` | call a read-only capability (e.g. `L1.rescan`) |
| GET | `/experience?signal=&asset=` | | history summary, per-strategy track record, similar past episodes |
| POST | `/agents/check` | `agent, tool, args, session, cwd, call_id` | judge an AI agent's tool call before it runs ([AGENTS.md](AGENTS.md)) |
| POST | `/agents/result` | `call_id, success, output` | report what the call returned (scanned for prompt injection) |
| GET | `/agents?agent=&limit=` | | agent guard status and recent calls |
| POST | `/agents/{agent}/release` | `by, reason` | a human unfreezes an agent (URL-encode ids containing `/`) |
| GET | `/audit?limit=100&prefix=action.` | | audit records |
| GET | `/audit/verify` | | verify the hash chain |

## Integrations

* **Identity events.** Forward IdP sign-ins, cloud audit logs (CloudTrail, Azure Activity, GCP Audit) or
  reverse-proxy logs to `POST /access-events`. If the gateway enforces the `allowed` result, AIPS acts as an
  inline policy decision point.
* **Telemetry.** Write JSON lines (`{"type":"metric","asset":"api","metric":"error_rate","value":0.02}`) from
  any exporter and add the file under `[telemetry] jsonl`.
* **Actions.** Map action kinds to commands in `[adapter.commands]`. Each value is validated before substitution.
* **Valves.** Implement `apply_valve(asset, kind, position)` on your adapter to push rate limits to Envoy
  (`local_ratelimit`), NGINX (`limit_req`), an API gateway, or queue-consumer concurrency.
* **Notifications.** HTTPS webhooks in `[notify] webhooks` (Slack, Teams or PagerDuty bridges).

## Runbook: common situations

| Situation | What to do |
|---|---|
| AIPS is doing something unexpected | `POST /killswitch {"engaged":true}`. All autonomy stops; approvals still work. |
| An incident is `failed` | Automation stopped after bounded attempts and rolled back reversible actions. See its timeline (`GET /incidents/{id}`). |
| A user was wrongly frozen | The user files `POST /appeals`; a different person reviews it with `grant=true`, optionally amending the boundary. |
| Ransomware alert | Vault replication is already held. Approve `host.isolate` and `backup.restore` (two people). The vault is untouched. |
| Audit verification fails | Treat it as a security incident. The first bad sequence number shows where tampering began. |
