# Running AIPS on Google Cloud

This guide takes AIPS from the simulator to a **real Google Cloud project you own**: discover the project, watch
it in dry run, then let AIPS act, and measure the results.

> Only run this against a project you own or are explicitly authorised to operate. The experiments below
> deliberately misconfigure **your own** test project. Never point AIPS, or these experiments, at anyone else's
> systems.

## What the integration does

| AIPS part | Google Cloud API |
|---|---|
| Inventory | Compute Engine: VMs, managed instance groups (MIGs), firewall rules; IAM service accounts |
| Level 1 telemetry | Cloud Monitoring (CPU; memory and disk with the Ops Agent; uptime checks), VM and MIG state, firewall rules as configuration (drift), internet-exposed ports computed with Google's rule priority semantics |
| Identity guard | Cloud Audit Logs: principal, method, resource, caller IP, success or failure |
| External alerts | Security Command Center findings (optional) |
| Actions | VM reset, MIG restart and resize, firewall deny rules, VM quarantine tag, firewall restore (drifted rules patched back, unapproved rules **disabled, never deleted**), service-account disable/enable. Each action has a rollback, and AIPS waits for every long-running operation to finish before verifying. |

The integration uses Google's REST APIs directly, with **no Google SDK required**. Credentials are tried in this
order:
1. the `AIPS_GCP_ACCESS_TOKEN` environment variable;
2. a service-account key (`GOOGLE_APPLICATION_CREDENTIALS`, needs `pip install "aips[crypto]"`);
3. the `gcloud` CLI;
4. the metadata server, when AIPS itself runs on a Compute Engine VM.

The integration is tested against `aips/integrations/gcp/emulator.py`, an in-process emulator of the same APIs
(`tests/test_gcp.py`). It includes end-to-end runs in which AIPS contains a rogue firewall rule, restarts a
crashed MIG, and disables a misused service account.

---

## Phase 0: project (you, in the browser, about 10 minutes)

1. Sign in at <https://console.cloud.google.com> and accept the terms. New accounts usually get free-trial credits.
2. Create a project, for example `aips-lab-<something>`, and note its **project ID**.
3. Make sure billing is linked (Compute Engine needs it). Set a **budget alert** (Billing → Budgets) so you are
   warned early about any cost.
4. Open **Cloud Shell** (the `>_` icon at the top right). It runs `gcloud` in your browser, so nothing needs to
   be installed on your PC.

## Phase 1: a small target system (Cloud Shell)

```bash
PROJECT=your-project-id ; ZONE=us-central1-a
gcloud config set project $PROJECT
gcloud services enable compute.googleapis.com monitoring.googleapis.com logging.googleapis.com iam.googleapis.com

# a 2-VM managed instance group running nginx
gcloud compute instance-templates create web-tpl --machine-type=e2-micro --tags=web \
  --image-family=debian-12 --image-project=debian-cloud \
  --metadata=startup-script='#!/bin/bash
apt-get update && apt-get install -y nginx'
gcloud compute instance-groups managed create web --zone=$ZONE --template=web-tpl --size=2
gcloud compute firewall-rules create allow-http --allow=tcp:80 --target-tags=web --source-ranges=0.0.0.0/0

# a service account that an "application" would use (the identity guard watches it)
gcloud iam service-accounts create app-sa --display-name="demo app"
```

## Phase 2: credentials for AIPS

**Quick start (dry run from your PC).** In Cloud Shell, run `gcloud auth print-access-token` and copy the output.
On your PC:

```powershell
$env:AIPS_GCP_ACCESS_TOKEN = "<paste>"      # valid for about 1 hour; uses your own permissions
aips gcp check --project your-project-id
aips gcp discover --project your-project-id --out runtime/gcp-inventory.toml
```

`check` reports OK, WARN or FAIL for each API. `discover` lists every VM, MIG and network, together with the
ports each one exposes to the internet.

**Recommended for longer runs (least privilege, no keys).** Run AIPS on a small VM whose own service account
has only the roles AIPS needs:

| Mode | Roles |
|---|---|
| Dry run (observe only) | `roles/compute.viewer`, `roles/monitoring.viewer`, `roles/logging.viewer`, `roles/iam.serviceAccountViewer` |
| Acting | add `roles/compute.instanceAdmin.v1` (reset, tags, MIG), `roles/compute.securityAdmin` (firewall rules); optionally `roles/iam.serviceAccountAdmin` (disable service accounts; powerful, grant only if you want that) |

Data-access audit logs (for example, reads from Secret Manager or Cloud Storage) are **off by default** in Google
Cloud. Enable them under *IAM & Admin → Audit Logs* for the services the identity guard should see.

## Phase 3: dry run (observe, change nothing)

1. Copy `examples/aips-gcp.toml`, set `project`, and keep `dry_run = true`.
2. Record the known-good firewall state (do this only when the project is in a reviewed, good state):
   ```powershell
   aips gcp baseline --config examples/aips-gcp.toml --approved-by you
   ```
3. Run for a while and keep a report:
   ```powershell
   aips run --config examples/aips-gcp.toml --ticks 60 --report runtime/gcp-dryrun.json
   ```
4. Read the incidents in the report (or at `GET /incidents`). Every false positive is a configuration fix to make
   before allowing AIPS to act: missing allowed ports, criticality, identity boundaries.

## Phase 4: experiments (your project only)

Run each one, first with `dry_run = true` (AIPS *plans*) and then with `dry_run = false` (AIPS *acts*). For each
run, record the time to detect, the time to resolve, the actions taken, and whether the result was correct.

| # | Do this in Cloud Shell | Expected AIPS behaviour |
|---|---|---|
| 1 | `gcloud compute firewall-rules create debug-open --allow=tcp:4444 --target-tags=web --source-ranges=0.0.0.0/0` | `unexpected_port` on each web VM plus `config_drift` (security-sensitive) on `net-default`. A deny rule `aips-block-4444-*` (priority 100) is created and `debug-open` is **disabled**; both are verified. |
| 2 | `gcloud compute firewall-rules update allow-http --source-ranges=0.0.0.0/0,1.2.3.4/32` | `config_drift` → `allow-http` patched back to its baseline source ranges |
| 3 | Stop one MIG VM: `gcloud compute instances stop <web-xxxx> --zone=$ZONE` | `service_down` on `web` → MIG restart. Note: the MIG may also heal itself; record which one acted first. |
| 4 | Misuse the app identity: `gcloud iam service-accounts keys create k.json --iam-account=app-sa@$PROJECT.iam.gserviceaccount.com` (then delete the key) | The audit log shows key creation by an identity whose boundary does not allow it → `boundary_violation` → freeze. With `serviceAccountAdmin` granted, the account is **disabled in IAM**; the appeal re-enables it. |
| 5 | CPU load on a web VM (`stress-ng` over SSH) | `cpu_saturated` → overload playbooks; the strategy learner records which variant worked |

## Phase 5: clean up (avoid charges)

```bash
gcloud compute instance-groups managed delete web --zone=$ZONE --quiet
gcloud compute instance-templates delete web-tpl --quiet
gcloud compute firewall-rules list --format="value(name)" | grep -E '^(aips-|debug-open)' | xargs -r -n1 gcloud compute firewall-rules delete --quiet
gcloud compute firewall-rules delete allow-http --quiet
gcloud iam service-accounts delete app-sa@$PROJECT.iam.gserviceaccount.com --quiet
```

Or delete the whole project: *IAM & Admin → Settings → Shut down*.

## Limits of this integration

* **Valves.** Valve positions are tracked inside AIPS but not yet pushed to Google Cloud. Enforcing them would
  need Cloud Armor rate-limiting rules or load-balancer capacity scaling, which is the next integration step.
* **Scope.** Regional MIGs are discovered but not acted on, because actions target zonal MIGs. GKE workloads are
  not integrated yet.
* **Human accounts.** Human users cannot be disabled through the IAM API. AIPS freezes them internally and
  notifies a human, who disables them in the Admin console.
