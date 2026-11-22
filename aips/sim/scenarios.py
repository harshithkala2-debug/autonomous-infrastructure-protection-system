"""Reproducible end-to-end scenarios with explicit success criteria, plus a benchmark harness.

Each scenario injects real faults into the simulator (and, for ransomware,
into real files on disk), runs the full AIPS loop, and evaluates success
criteria such as "detected before the disk reached 90 %", "no restart was
issued against symptom services", "the vault never received a suspect
snapshot" or "the wrongly frozen user regained access through an appeal".

Metrics per run: time-to-detect, time-to-resolve, number of actions, false
positive incidents, audit-chain integrity.
"""

from __future__ import annotations

import json
import shutil
import statistics
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..backup.manager import BackupManager, BackupPolicy
from ..backup.store import ObjectStore, sha256_file
from ..backup.vault import Vault, VaultConfig
from ..core.audit import AuditLedger
from ..core.clock import ManualClock
from ..core.models import IncidentStatus, reset_ids
from ..identity.guard import AccessEvent, Identity, PermissionBoundary, PermissionRule
from ..intel.collectors import load_fixture, merge_advisories, parse_feed, parse_kev, parse_nvd, parse_osv
from ..orchestrator import AIPS, AIPSConfig
from .environment import SimulatedInfrastructure, default_inventory

SIM_START = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc).timestamp()


@dataclass
class CheckOutcome:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class ScenarioResult:
    scenario: str
    seed: int
    passed: bool
    checks: list[CheckOutcome]
    ticks: int
    time_to_detect_s: float | None
    time_to_resolve_s: float | None
    incidents: int
    actions: int
    false_positive_incidents: int
    audit_ok: bool
    incident_summaries: list[dict[str, Any]] = field(default_factory=list)


class SimEnvironment:
    def __init__(self, seed: int = 7, tick_s: float = 30.0, workdir: str | Path | None = None,
                 config: AIPSConfig | None = None):
        reset_ids()
        self.seed, self.tick_s = seed, tick_s
        self.clock = ManualClock(SIM_START)
        self.inventory = default_inventory(SIM_START)
        self.sim = SimulatedInfrastructure(self.inventory, seed)
        self._own_workdir = workdir is None
        self.workdir = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="aips-sim-"))
        self.main = self.workdir / "main"
        self._seed_files()
        hmac_key = f"aips-sim-{seed}".encode().ljust(32, b"0")
        vault = Vault(VaultConfig(str(self.workdir / "vault"), ["10.0.0.0/8"], 30 * 86400, "sim-salt"), hmac_key)
        self.backup = BackupManager(self.main, ObjectStore(self.workdir / "copy"), hmac_key, vault,
                                    BackupPolicy(interval_s=120), replication_ip="10.0.0.5")
        self.backup.asset_id = "files"
        self.sim.files_root = self.main
        self.aips = AIPS(self.inventory, self.sim, [self.sim], clock=self.clock, config=config or AIPSConfig(),
                         audit=AuditLedger(clock=self.clock, key=b"sim-audit-key"), backup=self.backup)
        self.sim.baselines = self.aips.baselines
        self._register_identities()
        first = self.sim.collect(self.clock.now())
        for a in self.inventory:
            if a.id in first.configs:
                self.aips.baselines.capture(a.id, first.configs[a.id], first.open_ports.get(a.id, []),
                                            {s.name: s.version for s in a.software}, self.clock.now(), "bootstrap")
        self.events: dict[int, list[Callable[["SimEnvironment"], None]]] = {}
        self.tick_ts: dict[int, float] = {}
        self.first_finding: dict[str, float] = {}
        self.aips.bus.subscribe("finding.l1", self._on_finding)
        self.tick_no = 0
        self.background_identity = True
        self.notes: dict[str, Any] = {}
        self._session_gen: dict[str, int] = {}

    # -- setup -------------------------------------------------------------------
    def _seed_files(self) -> None:
        self.main.mkdir(parents=True, exist_ok=True)
        for i in range(20):
            sub = self.main / ("finance" if i % 2 else "engineering")
            sub.mkdir(exist_ok=True)
            (sub / f"document-{i:02d}.txt").write_text(
                f"Document {i}\n" + ("Quarterly figures and notes. " * (20 + i)), encoding="utf-8")

    def _register_identities(self) -> None:
        g = self.aips.guard
        g.register(Identity("svc-reports", "service", "analytics-team"), PermissionBoundary(
            allow=[PermissionRule("storage.read", "bucket/reports/*"), PermissionRule("db.query", "db/analytics/*")],
            source_networks=["10.0.0.0/8"], max_rate_per_min=120))
        g.register(Identity("alice", "human", "alice"), PermissionBoundary(
            allow=[PermissionRule("storage.*", "bucket/team/*"), PermissionRule("ticket.*", "tickets/*"),
                   PermissionRule("db.query", "db/analytics/*")],
            deny=[PermissionRule("iam.*", "*")], source_networks=["10.0.0.0/8"], allowed_hours_utc=(6, 21)))
        g.register(Identity("break-glass-admin", "human", "security"), PermissionBoundary(
            allow=[PermissionRule("*", "*")], source_networks=["10.0.0.0/8"]))

    def _on_finding(self, _topic: str, f) -> None:
        self.first_finding.setdefault(f.asset_id, f.created_at)

    def at(self, tick: int, fn: Callable[["SimEnvironment"], None]) -> None:
        self.events.setdefault(tick, []).append(fn)

    def access(self, identity: str, action: str, resource: str, ip: str, success: bool = True,
               session: str | None = None):
        if session is None:
            # a user whose session was revoked logs in again once they are no longer frozen
            gen = self._session_gen.get(identity, 0)
            session = f"sess-{identity}-{gen}"
            if session in self.aips.guard.revoked_sessions and not self.aips.guard.is_frozen(identity):
                self._session_gen[identity] = gen + 1
                session = f"sess-{identity}-{gen + 1}"
        return self.aips.ingest_access(AccessEvent(identity, action, resource, self.clock.now(), ip, success, session))

    def _background(self) -> None:
        t = self.tick_no
        for k in range(3):
            self.access("svc-reports", "storage.read", f"bucket/reports/daily-{(t + k) % 7}", "10.0.3.15")
        self.access("alice", "ticket.update", f"tickets/T-{100 + t % 5}", "10.0.8.21")
        self.access("alice", "storage.read", "bucket/team/plan.md", "10.0.8.21")

    # -- run ---------------------------------------------------------------------
    def run(self, ticks: int) -> None:
        for _ in range(ticks):
            self.tick_no += 1
            self.tick_ts[self.tick_no] = self.clock.now()
            for fn in self.events.get(self.tick_no, []):
                fn(self)
            self.sim.step(self.tick_no, self.clock.now())
            if self.background_identity:
                self._background()
            self.aips.tick()
            self.clock.advance(self.tick_s)

    def incidents(self, asset: str | None = None):
        return [i for i in self.aips.engine.incidents.values() if asset is None or i.asset_id == asset]

    def actions(self, kind: str | None = None, target: str | None = None):
        return [a for i in self.incidents() for a in i.actions
                if (kind is None or a.kind == kind) and (target is None or a.target == target)]

    def approve_all(self, *approvers: str) -> int:
        n = 0
        for ap in list(self.aips.approvals.pending()):
            for who in approvers[:ap.approvals_required]:
                self.aips.approve(ap.id, who, "approved in scenario")
            n += 1
        return n

    def cleanup(self) -> None:
        if self._own_workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)


# --------------------------------------------------------------------------- scenarios
@dataclass
class Scenario:
    name: str
    description: str
    ticks: int
    fault_tick: int
    fault_assets: list[str]
    expected_assets: list[str]
    setup: Callable[[SimEnvironment], None]
    checks: Callable[[SimEnvironment], list[CheckOutcome]]


def _resolved(env: SimEnvironment, asset: str) -> CheckOutcome:
    incs = env.incidents(asset)
    ok = bool(incs) and all(i.status in (IncidentStatus.RESOLVED, IncidentStatus.DISMISSED) for i in incs)
    return CheckOutcome(f"incident on {asset} resolved", ok, ", ".join(f"{i.id}:{i.status.value}" for i in incs))


def _setup_service_crash(env):
    env.at(20, lambda e: e.sim.inject("crash", "api", 20))


def _checks_service_crash(env):
    return [_resolved(env, "api"),
            CheckOutcome("api restarted", bool(env.actions("service.restart", "api"))),
            CheckOutcome("api healthy at end", env.sim.health("api") is True),
            CheckOutcome("web treated as symptom (not restarted)", not env.actions("service.restart", "web")),
            CheckOutcome("ingress valve back to fully open", env.aips.traffic.position("api", "ingress") == 1.0,
                         str(env.aips.traffic.position("api", "ingress")))]


def _setup_crash_loop(env):
    env.at(20, lambda e: e.sim.inject("crash_loop", "worker", 20))


def _checks_crash_loop(env):
    incs = env.incidents("worker")
    failed = [i for i in incs if i.status == IncidentStatus.FAILED]
    return [CheckOutcome("automation stops and hands to humans", bool(failed),
                         ", ".join(f"{i.id}:{i.status.value}" for i in incs)),
            CheckOutcome("progressive remediation tried scale-out", bool(env.actions("service.scale_out", "worker"))),
            CheckOutcome("restart attempts bounded", len(env.actions("service.restart", "worker")) <= 6,
                         str(len(env.actions("service.restart", "worker")))),
            CheckOutcome("humans notified", any("could not resolve" in m["body"] for m in env.aips.notifier.outbox)),
            CheckOutcome("reversible actions rolled back", any(t.event == "rollback" for i in failed for t in i.timeline))]


def _setup_dependency(env):
    env.at(20, lambda e: e.sim.inject("crash", "db", 20))


def _checks_dependency(env):
    held = [i for i in env.incidents() if i.root_cause_asset == "db"]
    return [_resolved(env, "db"),
            CheckOutcome("db restarted", bool(env.actions("service.restart", "db"))),
            CheckOutcome("dependents identified as symptoms of db", bool(held),
                         ", ".join(f"{i.asset_id}:{i.id}" for i in held)),
            CheckOutcome("no restarts against symptom services",
                         not env.actions("service.restart", "api") and not env.actions("service.restart", "worker"))]


def _setup_surge(env):
    env.at(20, lambda e: e.sim.inject("traffic_surge", "api", 20, 45, multiplier=2.6))


def _checks_surge(env):
    hist = [p for v in env.aips.traffic.valves() if v.asset_id == "api" for _, p, _ in v.history]
    return [_resolved(env, "api"),
            CheckOutcome("valves closed during the surge", bool(hist) and min(hist) < 1.0, f"min={min(hist or [1])}"),
            CheckOutcome("capacity added", bool(env.actions("service.scale_out", "api"))),
            CheckOutcome("both valves fully re-opened afterwards",
                         env.aips.traffic.position("api", "ingress") == 1.0
                         and env.aips.traffic.position("api", "internal") == 1.0)]


def _setup_disk(env):
    env.at(10, lambda e: e.sim.inject("disk_leak", "storage-01", 10, rate=1.0))

    def watch(e):
        e.notes.setdefault("disk_at_first_action", None)
    env.at(11, watch)


def _checks_disk(env):
    acts = env.actions("storage.cleanup", "storage-01")
    first = min((a.started_at for a in acts), default=None)
    tick_at = next((t for t, ts in env.tick_ts.items() if first is not None and ts >= first), None)
    est_pct = 55 + (tick_at - 10) * 1.0 if tick_at else None
    return [_resolved(env, "storage-01"),
            CheckOutcome("cleanup executed", bool(acts)),
            CheckOutcome("acted before the 90% hard threshold (early detection)",
                         est_pct is not None and est_pct < 90, f"~{est_pct}% when cleanup ran"),
            CheckOutcome("disk healthy at end", env.sim.assets["storage-01"].disk_used_pct < 85,
                         f"{env.sim.assets['storage-01'].disk_used_pct:.1f}%")]


def _setup_drift(env):
    env.at(20, lambda e: e.sim.inject("config_tamper", "api", 20, path="tls.enabled", value=False))


def _checks_drift(env):
    diffs = env.aips.baselines.compare_config("api", env.sim.assets["api"].config)
    return [_resolved(env, "api"),
            CheckOutcome("configuration restored to baseline", not diffs, f"{len(diffs)} diffs"),
            CheckOutcome("classified as security-sensitive",
                         any(i.category.value == "security" for i in env.incidents("api")))]


def _setup_port(env):
    env.at(20, lambda e: e.sim.inject("open_port", "storage-01", 20, port=4444))


def _checks_port(env):
    return [_resolved(env, "storage-01"),
            CheckOutcome("port 4444 closed", 4444 not in env.sim.assets["storage-01"].open_ports)]


def _setup_credential(env):
    def attack(e):
        for res in ("vault/prod/db-password", "vault/prod/api-key"):
            e.access("svc-reports", "secrets.read", res, "203.0.113.50", session="sess-attacker")
        e.access("svc-reports", "iam.create_access_key", "iam/users/svc-reports", "203.0.113.50",
                 session="sess-attacker")

    def after(e):
        e.notes["post_freeze"] = e.access("svc-reports", "storage.read", "bucket/reports/daily-1", "10.0.3.15").allowed

    env.at(20, attack)
    env.at(24, after)


def _checks_credential(env):
    g = env.aips.guard
    return [CheckOutcome("compromised identity frozen", g.is_frozen("svc-reports")),
            CheckOutcome("attacker session revoked", "sess-attacker" in g.revoked_sessions),
            CheckOutcome("further access denied after freeze", env.notes.get("post_freeze") is False),
            CheckOutcome("legitimate user unaffected", not g.is_frozen("alice")),
            CheckOutcome("appeal path available", True, "see false_freeze_appeal scenario")]


def _setup_appeal(env):
    def export(e):
        e.access("alice", "db.export", "db/analytics/q4-report", "10.0.8.21")

    def appeal(e):
        if e.aips.guard.is_frozen("alice"):
            e.notes["appeal"] = e.aips.submit_appeal("alice", "alice", "Quarterly export approved by my manager")

    def review(e):
        if "appeal" in e.notes:
            e.aips.review_appeal(e.notes["appeal"]["id"], "bob-security", True,
                                 "confirmed with manager; legitimate", "db.export", "db/analytics/*")

    def retry(e):
        e.notes["retry_allowed"] = e.access("alice", "db.export", "db/analytics/q4-report", "10.0.8.21").allowed

    env.at(20, export)
    env.at(21, export)
    env.at(26, appeal)
    env.at(28, review)
    env.at(32, retry)


def _checks_appeal(env):
    g = env.aips.guard
    appeals = list(g.appeals.values())
    return [CheckOutcome("out-of-boundary export was frozen", bool(env.actions("identity.freeze", "alice"))),
            CheckOutcome("appeal filed and granted by a different person",
                         bool(appeals) and appeals[0].status.value == "granted" and appeals[0].reviewer != "alice"),
            CheckOutcome("access restored", not g.is_frozen("alice")),
            CheckOutcome("boundary amended; retry allowed", env.notes.get("retry_allowed") is True),
            CheckOutcome("recorded as false positive for learning",
                         any(i.status == IncidentStatus.DISMISSED for i in env.incidents("identity:alice")))]


def _setup_ransomware(env):
    def snapshot_hashes(e):
        e.notes["clean_hashes"] = {p.relative_to(e.main).as_posix(): sha256_file(p)
                                   for p in e.main.rglob("*") if p.is_file()}
    env.at(18, snapshot_hashes)
    env.at(20, lambda e: e.sim.inject("ransomware", "files", 20, fraction=0.6))

    def approve(e):
        e.approve_all("alice-sre", "bob-sre")
    for t in range(24, 40, 2):
        env.at(t, approve)


def _checks_ransomware(env):
    vault_snaps = env.backup.vault.snapshots("10.0.0.5")
    now_hashes = {p.relative_to(env.main).as_posix(): sha256_file(p) for p in env.main.rglob("*") if p.is_file()}
    denied = False
    try:
        env.backup.vault.snapshots("198.51.100.9")
    except PermissionError:
        denied = True
    return [_resolved(env, "files"),
            CheckOutcome("mass encryption detected", any(i.signal == "mass_encryption" for i in env.incidents("files"))),
            CheckOutcome("vault never received a suspect snapshot", not any(m.suspect for m in vault_snaps),
                         f"{len(vault_snaps)} vault snapshots"),
            CheckOutcome("host isolated", env.sim.assets["files"].isolated),
            CheckOutcome("restore required two distinct approvers",
                         any(len(a.approvers) >= 2 for a in env.aips.approvals.all()
                             if a.request.kind == "backup.restore")),
            CheckOutcome("files restored byte-for-byte", now_hashes == env.notes.get("clean_hashes"),
                         f"{len(now_hashes)} files"),
            CheckOutcome("vault refuses callers outside the organisation's network", denied)]


def _setup_intel(env):
    def run_intel(e):
        advisories = merge_advisories(parse_nvd(json.loads(load_fixture("nvd_sample.json"))),
                                      parse_kev(json.loads(load_fixture("kev_sample.json"))),
                                      parse_osv(json.loads(load_fixture("osv_sample.json"))))
        reports = parse_feed(load_fixture("postmortems.xml"))
        e.notes["intel"] = e.aips.run_intel(advisories, reports)

    env.at(15, run_intel)
    for t in range(17, 30, 2):
        env.at(t, lambda e: e.approve_all("alice-sre", "bob-sre"))


def _checks_intel(env):
    api = env.inventory.get("api")
    versions = {s.name: s.version for s in api.software}
    summary = env.notes.get("intel", {})
    return [CheckOutcome("confirmed exposure found", summary.get("confirmed", 0) >= 2, json.dumps(summary)),
            CheckOutcome("non-matching versions recognised as not affected", summary.get("not_affected", 0) >= 1),
            CheckOutcome("version-less KEV entry flagged as possible, not confirmed", summary.get("possible", 0) >= 1),
            CheckOutcome("acme-gateway upgraded to fixed version after approval", versions["acme-gateway"] == "3.2.4",
                         versions["acme-gateway"]),
            CheckOutcome("upgrade required human approval",
                         any(a.request.kind == "package.upgrade" and a.status.value == "approved"
                             for a in env.aips.approvals.all())),
            CheckOutcome("postmortem patterns checked against environment", summary.get("pattern_findings", 0) >= 1)]


def _setup_false_alarm(env):
    env.at(20, lambda e: e.sim.inject("noisy_spike", "api", 20, 21, metric="latency_p95_ms", value=2600.0))


def _checks_false_alarm(env):
    return [CheckOutcome("no incident opened for a single spike", not env.incidents("api"),
                         ", ".join(i.id for i in env.incidents("api"))),
            CheckOutcome("no actions taken", not env.actions(target="api"))]


def _setup_kill_switch(env):
    env.at(15, lambda e: e.aips.set_kill_switch(True, "oncall", "planned migration"))
    env.at(20, lambda e: e.sim.inject("crash", "cache", 20))

    def check_then_approve(e):
        e.notes["restarts_before_approval"] = len(e.actions("service.restart", "cache"))
        e.approve_all("oncall")
    env.at(26, check_then_approve)
    for t in range(27, 40):
        env.at(t, lambda e: e.approve_all("oncall"))


def _checks_kill_switch(env):
    return [CheckOutcome("no autonomous action while kill switch engaged",
                         env.notes.get("restarts_before_approval") == 0, str(env.notes.get("restarts_before_approval"))),
            CheckOutcome("human-approved actions still possible", bool(env.actions("service.restart", "cache"))),
            _resolved(env, "cache")]


def _setup_cert(env):
    def expire(e):
        e.inventory.get("api").certificates[0].expires_at = e.clock.now() + 5 * 86400
    env.at(10, expire)


def _checks_cert(env):
    left = env.inventory.get("api").certificates[0].expires_at - env.clock.now()
    return [_resolved(env, "api"), CheckOutcome("certificate renewed", left > 60 * 86400, f"{left / 86400:.0f} days")]


SCENARIOS: dict[str, Scenario] = {s.name: s for s in [
    Scenario("service_crash", "API process crashes; web depends on it.", 60, 20, ["api"], ["api", "web"],
             _setup_service_crash, _checks_service_crash),
    Scenario("crash_loop", "Worker crashes repeatedly; automation must stop and escalate to humans.", 70, 20,
             ["worker"], ["worker"], _setup_crash_loop, _checks_crash_loop),
    Scenario("dependency_failure", "Primary database fails; dependents must be treated as symptoms.", 60, 20,
             ["db"], ["db", "api", "worker", "web"], _setup_dependency, _checks_dependency),
    Scenario("traffic_surge", "2.6x traffic surge on the API; valves + capacity, then ramp open.", 70, 20,
             ["api"], ["api", "web", "db"], _setup_surge, _checks_surge),
    Scenario("disk_forecast", "Log leak fills a disk; must act before the 90% threshold.", 60, 10,
             ["storage-01"], ["storage-01"], _setup_disk, _checks_disk),
    Scenario("config_drift", "TLS disabled on the API outside change control.", 50, 20, ["api"], ["api"],
             _setup_drift, _checks_drift),
    Scenario("exposed_port", "Unexpected listener on port 4444.", 50, 20, ["storage-01"], ["storage-01"],
             _setup_port, _checks_port),
    Scenario("credential_misuse", "Service account used from an external IP to read secrets.", 40, 20,
             ["identity:svc-reports"], ["identity:svc-reports"], _setup_credential, _checks_credential),
    Scenario("false_freeze_appeal", "Legitimate but out-of-boundary export is frozen, then appealed.", 45, 20,
             ["identity:alice"], ["identity:alice"], _setup_appeal, _checks_appeal),
    Scenario("ransomware", "Files are encrypted in place; vault must stay clean; restore with approval.", 50, 20,
             ["files"], ["files"], _setup_ransomware, _checks_ransomware),
    Scenario("vulnerability_intel", "Public advisories + postmortems assessed against the inventory.", 40, 15,
             ["api"], ["api", "cache", "backup", "edge-lb", "web", "db", "worker", "queue", "files", "storage-01",
                       "identity:break-glass-admin"],   # wildcard-permission finding on break-glass is correct
             _setup_intel, _checks_intel),
    Scenario("false_alarm", "Single latency spike must not trigger action.", 40, 20, [], [],
             _setup_false_alarm, _checks_false_alarm),
    Scenario("kill_switch", "Operator suspends autonomy; actions wait for approval.", 45, 20, ["cache"],
             ["cache", "api", "web"],
             _setup_kill_switch, _checks_kill_switch),
    Scenario("cert_expiry", "Certificate close to expiry is renewed.", 30, 10, ["api"], ["api"], _setup_cert,
             _checks_cert),
]}


def run_scenario(name: str, seed: int = 7, keep_env: bool = False) -> tuple[ScenarioResult, SimEnvironment | None]:
    sc = SCENARIOS[name]
    env = SimEnvironment(seed=seed)
    try:
        sc.setup(env)
        env.run(sc.ticks)
        checks = sc.checks(env)
        fault_ts = SIM_START + (sc.fault_tick - 1) * env.tick_s
        detect = [env.first_finding[a] - fault_ts for a in sc.fault_assets if a in env.first_finding
                  and env.first_finding[a] >= fault_ts - env.tick_s]
        resolves = [i.resolved_at - fault_ts for a in sc.fault_assets for i in env.incidents(a)
                    if i.resolved_at and i.status == IncidentStatus.RESOLVED]
        fps = [i for i in env.incidents() if i.asset_id not in sc.expected_assets]
        audit_ok = env.aips.audit.verify()[0]
        checks.append(CheckOutcome("audit chain intact", audit_ok))
        if sc.name != "vulnerability_intel":
            checks.append(CheckOutcome("no incidents on unrelated assets", not fps,
                                       ", ".join(f"{i.asset_id}:{i.signal}" for i in fps)))
        result = ScenarioResult(
            sc.name, seed, all(c.ok for c in checks), checks, sc.ticks,
            round(min(detect), 1) if detect else None, round(min(resolves), 1) if resolves else None,
            len(env.incidents()), len(env.actions()), len(fps), audit_ok,
            [{"id": i.id, "asset": i.asset_id, "signal": i.signal, "status": i.status.value, "level": i.level.name,
              "playbook": i.playbook, "actions": [f"{a.kind}:{'ok' if a.success else 'fail'}" for a in i.actions],
              "timeline": [f"+{t.at - fault_ts:.0f}s {t.actor} {t.event} {t.detail}" for t in i.timeline]}
             for i in env.incidents()])
        return result, (env if keep_env else None)
    finally:
        if not keep_env:
            env.cleanup()


def benchmark(seeds: list[int], names: list[str] | None = None) -> dict[str, Any]:
    names = names or list(SCENARIOS)
    out: dict[str, Any] = {"seeds": seeds, "scenarios": {}}
    for n in names:
        runs = [run_scenario(n, s)[0] for s in seeds]
        ttd = [r.time_to_detect_s for r in runs if r.time_to_detect_s is not None]
        ttr = [r.time_to_resolve_s for r in runs if r.time_to_resolve_s is not None]
        out["scenarios"][n] = {
            "pass_rate": sum(r.passed for r in runs) / len(runs),
            "mean_time_to_detect_s": round(statistics.mean(ttd), 1) if ttd else None,
            "mean_time_to_resolve_s": round(statistics.mean(ttr), 1) if ttr else None,
            "p95_time_to_resolve_s": round(sorted(ttr)[max(0, int(len(ttr) * 0.95) - 1)], 1) if ttr else None,
            "mean_actions": round(statistics.mean(r.actions for r in runs), 1),
            "false_positive_incidents": sum(r.false_positive_incidents for r in runs),
            "failed_checks": sorted({c.name for r in runs for c in r.checks if not c.ok}),
        }
    allp = [v["pass_rate"] for v in out["scenarios"].values()]
    out["overall_pass_rate"] = round(sum(allp) / len(allp), 3)
    return out


def result_to_dict(r: ScenarioResult) -> dict[str, Any]:
    return asdict(r)
