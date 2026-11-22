# Roadmap

## Next

* Native adapters: Kubernetes (client API), AWS / Azure / GCP SDKs, firewall APIs (nftables, cloud security
  groups), Envoy and NGINX valve integration.
* Durable distributed bus (Kafka / NATS) and a sharded orchestrator.
* OpenTelemetry and Prometheus remote-read telemetry sources.
* A shadow-mode comparison report that diffs AIPS decisions against operator actions on real incidents.

## Later

* Learned (but explainable) anomaly models alongside EWMA, with per-asset seasonality.
* Graph-based root-cause analysis using traces as well as declared dependencies.
* Policy-as-code (OPA/Rego) as an alternative to the built-in policy.
* A web console for approvals, appeals and incident timelines.
* Signed releases and an SBOM.
