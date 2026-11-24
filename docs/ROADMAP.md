# Roadmap

## Next

* AIPS web: run the live test across separate physical machines and a cloud VM over TLS; hub high availability
  (a standby hub); asymmetric node credentials (Ed25519 via the optional `cryptography` extra) so the hub cannot
  impersonate nodes; filesystem confinement for the Linux sandbox (Landlock / user namespaces); connect the
  Claude Code hook to the hybrid sandbox.

* AI agents: native integrations beyond the Claude Code hook (MCP gateway, LangChain/LangGraph, OpenAI Agents
  SDK), checkpointing for files written by programs an agent runs (file-system watcher), a shared allow-list of
  known-good commands per project, and a red-team corpus of obfuscated commands to measure rule evasion.

* Native adapters: Kubernetes (client API), AWS / Azure (GCP is done, via REST), firewall APIs (nftables, cloud security
  groups), Envoy and NGINX valve integration.
* Durable distributed bus (Kafka / NATS) and a sharded orchestrator.
* OpenTelemetry and Prometheus remote-read telemetry sources.
* A shadow-mode comparison report that diffs AIPS decisions against operator actions on real incidents.

## Later

* Learned (but explainable) anomaly models alongside EWMA, with per-asset seasonality (the 1.5 Isolation Forest
  covers node telemetry only).
* Graph-based root-cause analysis using traces as well as declared dependencies.
* Policy-as-code (OPA/Rego) as an alternative to the built-in policy.
* A web console for approvals, appeals and incident timelines.
* Signed releases and an SBOM.
