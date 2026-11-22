"""Response playbooks.

A playbook maps a signal to an ordered list of action steps plus the checks
that prove the problem is gone. Templates in ``target``/``params`` are filled
from the incident: ``{asset}``, ``{tag:<name>}`` (from the triggering
finding's tags) and ``{evidence:<key>}`` (from its first evidence record).

``priority`` drives conflict resolution between incidents that want to act
on the same target: lower number wins (containment > data integrity >
availability > performance).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from ..core.models import Category, Level

PRIORITY_CONTAINMENT = 0
PRIORITY_INTEGRITY = 1
PRIORITY_AVAILABILITY = 2
PRIORITY_PERFORMANCE = 3
PRIORITY_HYGIENE = 4


@dataclass
class Step:
    kind: str
    target: str = "{asset}"
    params: dict[str, Any] = field(default_factory=dict)
    min_attempt: int = 1            # run only from this attempt onward (progressive remediation)
    rollback_on_failure: bool = True


@dataclass
class Check:
    kind: str                       # healthy | metric_below | config_matches | port_closed | identity_frozen | signal_clear
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Playbook:
    name: str
    signals: list[str]
    level: Level
    steps: list[Step]
    checks: list[Check]
    priority: int = PRIORITY_AVAILABILITY
    categories: list[Category] | None = None
    max_attempts: int = 3
    required_passes: int = 2
    settle_ticks: int = 1
    release_valves: bool = True
    description: str = ""
    explorable: bool = True          # may take part in automatic strategy exploration

    def __post_init__(self) -> None:
        # never experiment with containment or data-integrity responses
        if self.priority <= PRIORITY_INTEGRITY:
            self.explorable = False

    def matches(self, signal: str, category: Category) -> bool:
        if self.categories and category not in self.categories:
            return False
        return any(fnmatch.fnmatch(signal, s) for s in self.signals)


def default_playbooks() -> list[Playbook]:
    return [
        Playbook(
            "service-recovery", ["service_down", "error_rate_critical"], Level.L2_EVALUATION,
            steps=[Step("traffic.throttle", params={"valve": "ingress", "position": 0.3}),
                   Step("service.restart"),
                   Step("service.scale_out", params={"replicas": 1}, min_attempt=2)],
            checks=[Check("healthy"), Check("metric_below", {"metric": "error_rate", "value": 0.05}),
                    Check("signal_clear")],
            priority=PRIORITY_AVAILABILITY,
            description="Shed load from the failing component, restart it, add capacity if it recurs."),
        Playbook(
            "elevated-errors", ["error_rate_high"], Level.L2_EVALUATION,
            steps=[Step("traffic.throttle", params={"valve": "ingress", "position": 0.6}),
                   Step("service.restart", min_attempt=2)],
            checks=[Check("metric_below", {"metric": "error_rate", "value": 0.05}), Check("signal_clear")],
            priority=PRIORITY_AVAILABILITY),
        Playbook(
            "overload-protection", ["overload", "cpu_saturated", "latency_high"],
            Level.L2_EVALUATION,
            steps=[Step("traffic.throttle", params={"valve": "ingress", "position": 0.5}),
                   Step("traffic.throttle", params={"valve": "internal", "position": 0.6}),
                   Step("service.scale_out", params={"replicas": 2})],
            checks=[Check("metric_below", {"metric": "saturation", "value": 0.8}), Check("signal_clear")],
            priority=PRIORITY_PERFORMANCE,
            description="Close both valves partially, then add capacity; valves ramp open after recovery."),
        Playbook(
            "storage-pressure", ["disk_forecast", "disk_full"], Level.L2_EVALUATION,
            steps=[Step("storage.cleanup", params={"paths": ["logs/rotated", "tmp"]}),
                   Step("storage.expand", params={"grow_pct": 50}, min_attempt=2)],
            checks=[Check("metric_below", {"metric": "disk_used_pct", "value": 85}), Check("signal_clear")],
            priority=PRIORITY_AVAILABILITY),
        # ---- alternative strategies (variants) for the same problems; chosen by StrategySelector ----
        Playbook(
            "restart-only", ["service_down", "error_rate_critical"], Level.L2_EVALUATION,
            steps=[Step("service.restart"),
                   Step("service.scale_out", params={"replicas": 1}, min_attempt=2)],
            checks=[Check("healthy"), Check("metric_below", {"metric": "error_rate", "value": 0.05}),
                    Check("signal_clear")],
            priority=PRIORITY_AVAILABILITY,
            description="Variant: restart immediately without shedding load first."),
        Playbook(
            "scale-then-restart", ["service_down", "error_rate_critical"], Level.L2_EVALUATION,
            steps=[Step("service.scale_out", params={"replicas": 1}), Step("service.restart")],
            checks=[Check("healthy"), Check("metric_below", {"metric": "error_rate", "value": 0.05}),
                    Check("signal_clear")],
            priority=PRIORITY_AVAILABILITY,
            description="Variant: add a healthy replica first, then restart the failing one."),
        Playbook(
            "restart-early", ["error_rate_high"], Level.L2_EVALUATION,
            steps=[Step("service.restart"),
                   Step("traffic.throttle", params={"valve": "ingress", "position": 0.6}, min_attempt=2)],
            checks=[Check("metric_below", {"metric": "error_rate", "value": 0.05}), Check("signal_clear")],
            priority=PRIORITY_AVAILABILITY,
            description="Variant: restart first, throttle only if that does not help."),
        Playbook(
            "scale-first", ["overload", "cpu_saturated", "latency_high"], Level.L2_EVALUATION,
            steps=[Step("service.scale_out", params={"replicas": 2}),
                   Step("traffic.throttle", params={"valve": "ingress", "position": 0.5}, min_attempt=2)],
            checks=[Check("metric_below", {"metric": "saturation", "value": 0.8}), Check("signal_clear")],
            priority=PRIORITY_PERFORMANCE,
            description="Variant: add capacity immediately; throttle only if that is not enough."),
        Playbook(
            "shed-load", ["overload", "cpu_saturated", "latency_high"], Level.L2_EVALUATION,
            steps=[Step("traffic.throttle", params={"valve": "ingress", "position": 0.4}),
                   Step("service.scale_out", params={"replicas": 2}, min_attempt=2)],
            checks=[Check("metric_below", {"metric": "saturation", "value": 0.8}), Check("signal_clear")],
            priority=PRIORITY_PERFORMANCE,
            description="Variant: protect the component by shedding load only (cheap, may not hold)."),
        Playbook(
            "expand-first", ["disk_forecast", "disk_full"], Level.L2_EVALUATION,
            steps=[Step("storage.expand", params={"grow_pct": 50}),
                   Step("storage.cleanup", params={"paths": ["logs/rotated", "tmp"]}, min_attempt=2)],
            checks=[Check("metric_below", {"metric": "disk_used_pct", "value": 85}), Check("signal_clear")],
            priority=PRIORITY_AVAILABILITY,
            description="Variant: grow the volume first (needs Level 3 authority), clean up if still short."),
        Playbook(
            "config-restore", ["config_drift"], Level.L3_DECISION,
            steps=[Step("config.restore_baseline")],
            checks=[Check("config_matches"), Check("signal_clear")],
            priority=PRIORITY_INTEGRITY,
            description="Revert to the recorded known-good configuration."),
        Playbook(
            "close-exposed-port", ["unexpected_port"], Level.L3_DECISION,
            steps=[Step("network.block_port", params={"port": "{tag:port}"})],
            checks=[Check("port_closed", {"port": "{tag:port}"}), Check("signal_clear")],
            priority=PRIORITY_CONTAINMENT),
        Playbook(
            "certificate-renewal", ["cert_expiry"], Level.L2_EVALUATION,
            steps=[Step("cert.renew", params={"cert": "{tag:cert}"})],
            checks=[Check("signal_clear")],
            priority=PRIORITY_HYGIENE),
        Playbook(
            "identity-containment", ["boundary_violation", "credential_misuse", "identity_anomaly"],
            Level.L3_DECISION,
            steps=[Step("identity.freeze", target="{tag:identity}"),
                   Step("identity.revoke_sessions", target="{tag:identity}", rollback_on_failure=False),
                   Step("identity.revert_actions", target="{tag:identity}"),
                   Step("notify.humans", params={"message": "Identity {tag:identity} frozen; appeal available"})],
            checks=[Check("identity_frozen", {"identity": "{tag:identity}"})],
            priority=PRIORITY_CONTAINMENT, required_passes=1, release_valves=False,
            description="Freeze the identity, revoke its sessions, notify owners (appeal path open)."),
        Playbook(
            "ransomware-containment", ["mass_encryption"], Level.L3_DECISION,
            steps=[Step("backup.hold_replication"),
                   Step("host.isolate"),
                   Step("notify.humans", params={"message": "Possible ransomware on {asset}; vault replication held"}),
                   Step("backup.restore", params={"snapshot": "latest_clean"})],
            checks=[Check("signal_clear")],
            priority=PRIORITY_CONTAINMENT, max_attempts=1, required_passes=1, release_valves=False,
            description="Stop propagation to the vault, isolate, restore from last clean snapshot (approved)."),
        Playbook(
            "vulnerability-remediation", ["vulnerable_component"], Level.L3_DECISION,
            steps=[Step("notify.humans", params={"message": "{asset}: {tag:advisory} affects {tag:package}"}),
                   Step("package.upgrade", params={"package": "{tag:package}", "version": "{tag:fixed_version}"})],
            checks=[Check("signal_clear")],
            priority=PRIORITY_INTEGRITY, max_attempts=1, required_passes=1, release_valves=False),
        Playbook(
            "failure-pattern-review", ["intel_pattern:*"], Level.L2_EVALUATION,
            steps=[Step("notify.humans", params={"message": "{asset}: exposure to failure pattern {tag:pattern}"})],
            checks=[], priority=PRIORITY_HYGIENE, max_attempts=1, required_passes=0, release_valves=False),
        Playbook(
            "possible-exposure-review", ["possible_exposure"], Level.L2_EVALUATION,
            steps=[Step("notify.humans", params={
                "message": "{asset}: {tag:advisory} may affect {tag:package} {tag:installed}; confirm version"})],
            checks=[], priority=PRIORITY_HYGIENE, max_attempts=1, required_passes=0, release_valves=False),
        Playbook(
            "replication-lag", ["replication_lag"], Level.L2_EVALUATION,
            steps=[Step("traffic.throttle", params={"valve": "internal", "position": 0.5})],
            checks=[Check("metric_below", {"metric": "replication_lag_s", "value": 60}), Check("signal_clear")],
            priority=PRIORITY_INTEGRITY),
    ]


# When several signals fire on one asset in the same cycle, the most causal one is handled first and
# opens the incident; the others attach to it as correlated symptoms. Lower index = more causal.
SIGNAL_PRECEDENCE = [
    "mass_encryption", "boundary_violation", "credential_misuse", "unexpected_port", "config_drift",
    "service_down", "overload", "disk_full", "disk_forecast", "cpu_saturated", "memory_pressure",
    "replication_lag", "error_rate_critical", "error_rate_high", "latency_high", "cert_expiry",
    "vulnerable_component", "identity_anomaly",
]


def signal_rank(signal: str) -> int:
    if signal.startswith("anomaly:"):
        return len(SIGNAL_PRECEDENCE) + 1
    try:
        return SIGNAL_PRECEDENCE.index(signal)
    except ValueError:
        return len(SIGNAL_PRECEDENCE)


class PlaybookLibrary:
    def __init__(self, playbooks: list[Playbook] | None = None):
        self.playbooks = playbooks if playbooks is not None else default_playbooks()

    def select(self, signal: str, category: Category) -> Playbook | None:
        """The canonical (first-listed) playbook for a signal."""
        for pb in self.playbooks:
            if pb.matches(signal, category):
                return pb
        return None

    def candidates(self, signal: str, category: Category) -> list[Playbook]:
        """Every strategy that can handle this signal, canonical first."""
        return [pb for pb in self.playbooks if pb.matches(signal, category)]

    def get(self, name: str) -> Playbook | None:
        return next((p for p in self.playbooks if p.name == name), None)

    def l2_signals(self) -> list[str]:
        return [s for p in self.playbooks if p.level == Level.L2_EVALUATION for s in p.signals]
