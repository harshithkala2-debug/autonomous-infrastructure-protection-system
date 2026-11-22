"""Failure-pattern extraction from public incident reports and postmortems.

A postmortem about another organisation is *intelligence, not proof*. This
module (1) extracts the technical failure pattern(s) a report describes, then
(2) runs a concrete environment check for each pattern against the
customer's own inventory and AIPS state. Only checks that find a matching
condition produce findings - the report itself never does.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..telemetry.inventory import Inventory
from .models import IncidentReport


@dataclass
class EnvContext:
    inventory: Inventory
    now: float = field(default_factory=time.time)
    backup_status: dict[str, Any] | None = None
    identity_boundaries: dict[str, Any] | None = None
    drill_interval_s: float = 7 * 86400


Check = Callable[[EnvContext], list[tuple[str, str]]]


def _attr(asset, key, default=None):
    return asset.attributes.get(key, default)


def check_cert_expiry(ctx: EnvContext) -> list[tuple[str, str]]:
    out = []
    for a in ctx.inventory:
        for c in a.certificates:
            days = (c.expires_at - ctx.now) / 86400
            if days < 45:
                out.append((a.id, f"certificate '{c.name}' expires in {days:.0f} days"))
        if a.certificates and not _attr(a, "cert_auto_renew", False):
            out.append((a.id, "certificates are not auto-renewed"))
    return out


def check_staged_rollout(ctx: EnvContext) -> list[tuple[str, str]]:
    return [(a.id, "configuration/deploys are not rolled out in stages (no canary)")
            for a in ctx.inventory if a.kind == "service" and a.criticality >= 3
            and not _attr(a, "staged_rollout", False)]


def check_dns(ctx: EnvContext) -> list[tuple[str, str]]:
    out = []
    for a in ctx.inventory:
        providers = _attr(a, "dns_providers")
        if providers is not None and len(providers) < 2 and a.criticality >= 4:
            out.append((a.id, f"single DNS provider ({providers[0] if providers else 'none'})"))
    return out


def check_capacity(ctx: EnvContext) -> list[tuple[str, str]]:
    return [(a.id, "critical service without autoscaling")
            for a in ctx.inventory if a.kind == "service" and a.criticality >= 4 and not _attr(a, "autoscaling", False)]


def check_single_point(ctx: EnvContext) -> list[tuple[str, str]]:
    out = []
    for a in ctx.inventory:
        deps = ctx.inventory.dependents(a.id)
        if len(deps) >= 2 and int(_attr(a, "replicas", 1)) < 2:
            out.append((a.id, f"single instance with {len(deps)} dependents ({', '.join(deps)})"))
    return out


def check_retry_storm(ctx: EnvContext) -> list[tuple[str, str]]:
    return [(a.id, "no client rate limiting / circuit breaker configured")
            for a in ctx.inventory if a.kind == "service" and a.depends_on
            and not (_attr(a, "rate_limited", False) or _attr(a, "circuit_breaker", False))]


def check_clock(ctx: EnvContext) -> list[tuple[str, str]]:
    return [(a.id, "no time synchronisation (NTP/PTP) configured")
            for a in ctx.inventory if a.kind == "host" and not _attr(a, "ntp", False)]


def check_overprivilege(ctx: EnvContext) -> list[tuple[str, str]]:
    out = []
    for iid, b in (ctx.identity_boundaries or {}).items():
        for r in getattr(b, "allow", []):
            if r.action in ("*", "*.*") and r.resource == "*":
                out.append((f"identity:{iid}", "identity has unrestricted wildcard permissions"))
    for a in ctx.inventory:
        if _attr(a, "secrets_in_env", False):
            out.append((a.id, "secrets supplied via plain environment variables"))
    return out


def check_backups(ctx: EnvContext) -> list[tuple[str, str]]:
    st = ctx.backup_status
    if st is None:
        return [("backup", "no backup system is configured")]
    drill = st.get("last_drill")
    if not drill:
        return [("backup", "backups have never been restore-tested")]
    if not drill.get("ok"):
        return [("backup", f"last restore drill failed: {drill.get('errors')}")]
    if ctx.now - float(drill.get("at", 0)) > ctx.drill_interval_s:
        return [("backup", "last successful restore drill is older than the drill interval")]
    return []


def check_db_failover(ctx: EnvContext) -> list[tuple[str, str]]:
    return [(a.id, "database failover is untested or no replica exists")
            for a in ctx.inventory if a.kind == "database"
            and (int(_attr(a, "replicas", 1)) < 2 or not _attr(a, "failover_tested", False))]


def check_routing(ctx: EnvContext) -> list[tuple[str, str]]:
    return [(a.id, "single upstream transit / routing provider")
            for a in ctx.inventory if a.kind == "network" and len(_attr(a, "transit_providers", ["x"])) < 2]


@dataclass
class FailurePattern:
    id: str
    name: str
    keywords: list[str]
    check: Check
    recommendation: str

    def __post_init__(self) -> None:
        self._re = [re.compile(k, re.IGNORECASE) for k in self.keywords]

    def score(self, text: str) -> int:
        return sum(1 for r in self._re if r.search(text))


PATTERNS: list[FailurePattern] = [
    FailurePattern("cert_expiry", "Certificate expiry",
                   [r"certificate.{0,20}expir", r"expired (tls|ssl)? ?cert", r"\bcert(ificate)? rotation"],
                   check_cert_expiry, "Automate renewal and alert at 30/7 days before expiry."),
    FailurePattern("bad_config_push", "Global configuration / deploy push",
                   [r"config(uration)? (change|push|update)", r"bad (deploy|release|push)", r"rolled back",
                    r"global(ly)? (deploy|rollout)", r"without (a )?canary"],
                   check_staged_rollout, "Roll out configuration in stages with automatic rollback."),
    FailurePattern("dns", "DNS failure", [r"\bdns\b", r"name resolution", r"resolver"],
                   check_dns, "Use multiple authoritative DNS providers and sane TTLs."),
    FailurePattern("capacity", "Capacity exhaustion",
                   [r"capacity", r"overload", r"traffic (spike|surge)", r"thundering herd", r"exhaust"],
                   check_capacity, "Enable autoscaling and load shedding for critical services."),
    FailurePattern("single_point", "Single point of failure / dependency outage",
                   [r"single point of failure", r"dependency", r"upstream (outage|failure)", r"cascad"],
                   check_single_point, "Run redundant instances for shared dependencies."),
    FailurePattern("retry_storm", "Retry storm", [r"retr(y|ies) storm", r"retr(y|ies)", r"backoff"],
                   check_retry_storm, "Add client-side rate limits, jittered backoff and circuit breakers."),
    FailurePattern("clock", "Clock skew / leap second", [r"clock (skew|drift)", r"leap second", r"\bntp\b"],
                   check_clock, "Enforce time synchronisation and monitor skew."),
    FailurePattern("credential_leak", "Leaked or over-privileged credentials",
                   [r"(leaked|exposed|stolen) (credential|key|token|secret)", r"over-?privileged",
                    r"access key", r"credential"],
                   check_overprivilege, "Scope identities to least privilege; move secrets to a vault."),
    FailurePattern("backup_failure", "Backups unusable when needed",
                   [r"backup", r"restore (failed|failure)", r"data loss", r"ransomware"],
                   check_backups, "Keep isolated immutable copies and run regular restore drills."),
    FailurePattern("db_failover", "Database failover failure",
                   [r"failover", r"replica(tion)? (lag|failure)", r"split.brain", r"primary database"],
                   check_db_failover, "Maintain replicas and exercise failover regularly."),
    FailurePattern("routing", "BGP / routing failure", [r"\bbgp\b", r"route leak", r"routing"],
                   check_routing, "Use multiple transit providers and RPKI route validation."),
]


def extract_patterns(report: IncidentReport, min_score: int = 1) -> list[tuple[FailurePattern, int]]:
    text = f"{report.title}\n{report.text}"
    scored = [(p, p.score(text)) for p in PATTERNS]
    return sorted([(p, s) for p, s in scored if s >= min_score], key=lambda x: -x[1])
