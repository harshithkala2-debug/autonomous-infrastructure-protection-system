"""Build a production AIPS instance from a TOML configuration file.

See ``examples/aips.toml`` for a fully commented example. Secrets (audit HMAC
key, backup keys, API token, NVD API key) are never stored in the file: the
file names the *environment variable* that holds each one.
"""

from __future__ import annotations

import logging
import os
import time
import tomllib
from pathlib import Path
from typing import Any

from .backup.manager import BackupManager, BackupPolicy
from .backup.store import Cipher, ObjectStore
from .backup.vault import Vault, VaultConfig, ensure_dir_private
from .core.audit import AuditLedger
from .core.policy import PolicyConfig
from .evaluation.escalation import EscalationConfig
from .evaluation.evaluator import EvaluatorConfig
from .experience.store import ExperienceStore
from .identity.guard import GuardConfig, Identity, IdentityGuard, PermissionBoundary
from .monitoring.detectors import DEFAULT_THRESHOLDS, ThresholdRule
from .orchestrator import AIPS, AIPSConfig
from .repair.baseline import DesiredStateStore
from .repair.executor import CommandAdapter, Notifier, RecordingAdapter
from .telemetry.inventory import Inventory
from .telemetry.sources import HostTelemetrySource, JsonlTelemetrySource
from .traffic.valves import ValveConfig


class ConfigError(ValueError):
    pass


def _secret(section: dict[str, Any], key: str, required: bool = False) -> bytes | None:
    env = section.get(f"{key}_env")
    if not env:
        if required:
            raise ConfigError(f"'{key}_env' must name an environment variable")
        return None
    val = os.environ.get(env)
    if not val:
        if required:
            raise ConfigError(f"environment variable {env} is not set")
        return None
    try:
        return bytes.fromhex(val) if len(val) in (64, 128) and all(c in "0123456789abcdefABCDEF" for c in val) \
            else val.encode()
    except ValueError:
        return val.encode()


def load_config(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    data["_base"] = str(path.resolve().parent)
    return data


def _p(base: str, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else Path(base) / p


def build(cfg: dict[str, Any]) -> AIPS:
    base = cfg.get("_base", ".")
    core = cfg.get("aips", {})
    data_dir = _p(base, core.get("data_dir", "aips-data"))
    ensure_dir_private(data_dir)

    gcp_cfg = cfg.get("gcp")
    gcp_client = gcp_topology = None
    if gcp_cfg:
        from .integrations.gcp import GcpClient, GcpDiscovery, default_token_provider
        if not gcp_cfg.get("project"):
            raise ConfigError("[gcp] project is required")
        gcp_client = GcpClient(gcp_cfg["project"], default_token_provider())

    inv_path = cfg.get("inventory", {}).get("path")
    if inv_path:
        inventory = Inventory.load(_p(base, inv_path))
    elif gcp_client is not None:
        try:
            gcp_topology = GcpDiscovery(gcp_client).topology()
            inventory = GcpDiscovery.inventory(gcp_topology, gcp_cfg.get("criticality", {}))
        except Exception as exc:  # noqa: BLE001 - expired token, network blip: start anyway and retry each cycle
            logging.getLogger("aips.config").error("Google Cloud discovery failed at start-up (%s); "
                                                   "AIPS will keep retrying every cycle", exc)
            gcp_topology, inventory = None, Inventory([])
    else:
        raise ConfigError("[inventory] path is required (or a [gcp] section for automatic discovery)")

    thresholds = list(DEFAULT_THRESHOLDS)
    if cfg.get("thresholds"):
        thresholds = [ThresholdRule.from_dict(t) for t in cfg["thresholds"]]

    policy = PolicyConfig.from_dict(cfg.get("policy", {}))
    if core.get("dry_run") is not None:
        policy.dry_run = bool(core["dry_run"])
    strat = cfg.get("strategy", {})
    acfg = AIPSConfig(policy=policy, escalation=EscalationConfig.from_dict(cfg.get("escalation", {})),
                      evaluator=EvaluatorConfig.from_dict(cfg.get("evaluator", {})),
                      valves=ValveConfig(**cfg.get("valves", {})), thresholds=thresholds,
                      strategy_exploration=bool(strat.get("exploration", True)),
                      strategy_seed=int(strat.get("seed", 0)))

    baselines = DesiredStateStore(data_dir / "baselines.json")
    acfg_adapter = cfg.get("adapter", {"type": "recording"})
    if acfg_adapter.get("type") == "command":
        adapter = CommandAdapter.from_config(acfg_adapter.get("commands", {}))
    elif acfg_adapter.get("type") == "gcp":
        if gcp_client is None:
            raise ConfigError("adapter type 'gcp' needs a [gcp] section")
        from .integrations.gcp import GcpAdapter
        adapter = GcpAdapter(gcp_client, gcp_topology, baselines)
    elif acfg_adapter.get("type", "recording") == "recording":
        adapter = RecordingAdapter()
    else:
        raise ConfigError(f"unknown adapter type {acfg_adapter.get('type')}")

    sources = []
    tel = cfg.get("telemetry", {})
    if "host" in tel:
        h = tel["host"]
        sources.append(HostTelemetrySource(h.get("asset_id", "localhost"), h.get("disk_paths"), h.get("probes"),
                                           h.get("config_files"), listening_ports=bool(h.get("listening_ports"))))
    for j in tel.get("jsonl", []):
        sources.append(JsonlTelemetrySource(_p(base, j)))
    if gcp_client is not None and gcp_cfg.get("telemetry", True):
        from .integrations.gcp import GcpTelemetrySource
        src = GcpTelemetrySource(gcp_client, dict(gcp_cfg.get("uptime_checks", {})),
                                 float(gcp_cfg.get("window_s", 600)), audit_logs=bool(gcp_cfg.get("audit_logs", True)),
                                 scc=bool(gcp_cfg.get("security_command_center", False)),
                                 monitoring=bool(gcp_cfg.get("monitoring", True)))
        src.topology = gcp_topology
        if gcp_topology is not None:
            src._topo_at = time.time()
        crit = dict(gcp_cfg.get("criticality", {}))
        # continuous discovery: assets found later (new VMs, or after a failed start-up) join the inventory
        src.on_topology = lambda topo: [inventory.add(a) for a in GcpDiscovery.inventory(topo, crit)
                                        if inventory.get(a.id) is None]
        sources.append(src)

    audit_cfg = cfg.get("audit", {})
    audit = AuditLedger(data_dir / "audit.jsonl", key=_secret(audit_cfg, "hmac_key"))

    backup = None
    if "backup" in cfg:
        b = cfg["backup"]
        hk = _secret(b, "hmac_key", required=True)
        ek = _secret(b, "encryption_key")
        cipher = Cipher(ek) if ek else None
        vault = None
        if "vault" in b:
            v = b["vault"]
            vault = Vault(VaultConfig(str(_p(base, v["root"])), list(v["allowed_networks"]),
                                      float(v.get("retention_lock_days", 30)) * 86400,
                                      (_secret(v, "ip_salt") or b"").decode(errors="ignore")), hk, cipher)
        pol = BackupPolicy(**{k: v for k, v in b.get("policy", {}).items()})
        backup = BackupManager(_p(base, b["main"]), ObjectStore(_p(base, b["copy"]), cipher), hk, vault, pol,
                               b.get("replication_ip"), tuple(b.get("exclude", [])))
        backup.asset_id = b.get("asset_id", "backup")

    notifier = Notifier(cfg.get("notify", {}).get("webhooks", []))
    exp_path = cfg.get("experience", {}).get("path")
    experience = ExperienceStore(_p(base, exp_path) if exp_path else data_dir / "experience.db")
    guard = IdentityGuard(GuardConfig(auto_register_unknown=bool((gcp_cfg or {}).get("learn_identities", False))))
    aips = AIPS(inventory, adapter, sources, config=acfg, audit=audit, baselines=baselines,
                backup=backup, notifier=notifier, experience=experience, guard=guard)

    for ident in cfg.get("identities", []):
        aips.guard.register(Identity(ident["id"], ident.get("kind", "human"), ident.get("owner", ""),
                                     ident.get("roles", [])),
                            PermissionBoundary.from_dict(ident.get("boundary", {})))
    aips.data_dir = data_dir  # type: ignore[attr-defined]
    return aips
