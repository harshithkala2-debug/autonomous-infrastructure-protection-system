"""Command-line interface.

    aips demo [--scenario NAME|all] [--seed N] [--verbose] [--json FILE]
    aips scenarios
    aips bench [--seeds 1-10] [--json FILE]
    aips run --config aips.toml [--once] [--no-api]
    aips audit verify FILE [--key-env VAR]
    aips backup {snapshot,replicate,verify,restore,drill,prune,status} --config aips.toml
    aips intel assess --config aips.toml [--offline] [--sources nvd,kev,osv,feeds]
    aips experience --db aips-data/experience.db [--signal overload] [--asset api]
    aips gcp {check,discover} --project PROJECT [--out inventory.toml]
    aips gcp baseline --config aips-gcp.toml --approved-by NAME
    aips version
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from . import __version__


def _parse_seeds(s: str) -> list[int]:
    out: list[int] = []
    for part in s.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def cmd_scenarios(_args) -> int:
    from .sim.scenarios import SCENARIOS
    for s in SCENARIOS.values():
        print(f"{s.name:22s} {s.ticks:3d} ticks  {s.description}")
    return 0


def cmd_demo(args) -> int:
    logging.disable(logging.CRITICAL)
    from .sim.scenarios import SCENARIOS, result_to_dict, run_scenario
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        print(f"unknown scenario(s): {', '.join(unknown)}; see `aips scenarios`", file=sys.stderr)
        return 2
    results = []
    width = max(len(n) for n in names)
    for n in names:
        r, _ = run_scenario(n, args.seed)
        results.append(r)
        status = "PASS" if r.passed else "FAIL"
        ttd = f"{r.time_to_detect_s:.0f}s" if r.time_to_detect_s is not None else "-"
        ttr = f"{r.time_to_resolve_s:.0f}s" if r.time_to_resolve_s is not None else "-"
        print(f"[{status}] {n:{width}s}  detect {ttd:>5s}  resolve {ttr:>5s}  incidents {r.incidents:2d}  "
              f"actions {r.actions:2d}")
        for c in r.checks:
            if args.verbose or not c.ok:
                print(f"         {'ok ' if c.ok else 'XX '} {c.name}" + (f"  ({c.detail})" if c.detail else ""))
        if args.verbose:
            for inc in r.incident_summaries:
                print(f"         - {inc['id']} {inc['asset']} {inc['signal']} -> {inc['status']} "
                      f"[{inc['level']}, {inc['playbook']}]")
                for t in inc["timeline"]:
                    print(f"             {t}")
    passed = sum(r.passed for r in results)
    print(f"\n{passed}/{len(results)} scenarios passed")
    if args.json:
        Path(args.json).write_text(json.dumps([result_to_dict(r) for r in results], indent=2, default=str))
        print(f"results written to {args.json}")
    return 0 if passed == len(results) else 1


def cmd_bench(args) -> int:
    logging.disable(logging.CRITICAL)
    from .sim.scenarios import benchmark
    seeds = _parse_seeds(args.seeds)
    t0 = time.time()
    out = benchmark(seeds, args.scenario.split(",") if args.scenario else None)
    out["wall_time_s"] = round(time.time() - t0, 1)
    print(f"{'scenario':22s} {'pass':>6s} {'MTTD':>7s} {'MTTR':>7s} {'p95 TTR':>8s} {'actions':>8s} {'FP inc':>7s}")
    for n, s in out["scenarios"].items():
        def f(v):
            return f"{v:.0f}s" if isinstance(v, (int, float)) else "-"
        print(f"{n:22s} {s['pass_rate']:6.0%} {f(s['mean_time_to_detect_s']):>7s} {f(s['mean_time_to_resolve_s']):>7s} "
              f"{f(s['p95_time_to_resolve_s']):>8s} {s['mean_actions']:8.1f} {s['false_positive_incidents']:7d}")
    print(f"\noverall pass rate {out['overall_pass_rate']:.1%} over {len(seeds)} seed(s) in {out['wall_time_s']}s")
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=2))
    return 0 if out["overall_pass_rate"] == 1.0 else 1


def cmd_run(args) -> int:
    from .api.server import serve
    from .config import build, load_config
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(args.config)
    aips = build(cfg)
    lock = threading.RLock()
    tick_s = float(cfg.get("aips", {}).get("tick_seconds", 30))
    srv = None
    api = cfg.get("api", {})
    if not args.no_api and api.get("enabled", True):
        token = os.environ.get(api.get("token_env", "AIPS_API_TOKEN"), "")
        srv = serve(aips, api.get("host", "127.0.0.1"), int(api.get("port", 8780)), token, lock)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    if args.tick_seconds:
        tick_s = args.tick_seconds
    limit = 1 if args.once else args.ticks
    while not stop.is_set():
        t0 = time.time()
        with lock:
            rep = aips.tick()
        logging.getLogger("aips").info("tick %d: %d findings, %d active incidents", rep.tick, rep.findings,
                                       rep.active_incidents)
        if limit and rep.tick >= limit:
            break
        stop.wait(max(0.0, tick_s - (time.time() - t0)))
    if srv:
        srv.shutdown()
    if args.report:
        from .core.models import to_jsonable
        report = {"status": aips.status(),
                  "incidents": [to_jsonable(i) for i in aips.engine.incidents.values()],
                  "pending_approvals": [{"id": a.id, "kind": a.request.kind, "target": a.request.target,
                                         "reason": a.reason} for a in aips.approvals.pending()],
                  "notifications": aips.notifier.outbox,
                  "observation": to_jsonable(aips.last_obs)}
        Path(args.report).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return 0


def cmd_audit(args) -> int:
    from .core.audit import AuditLedger
    key = os.environ.get(args.key_env).encode() if args.key_env and os.environ.get(args.key_env) else None
    ok, bad, reason = AuditLedger.verify_file(args.file, key)
    print(("OK   " if ok else "BAD  ") + reason + (f" (first bad record: {bad})" if bad else ""))
    return 0 if ok else 1


def cmd_backup(args) -> int:
    from .config import build, load_config
    aips = build(load_config(args.config))
    b = aips.backup
    if b is None:
        print("no [backup] section in configuration", file=sys.stderr)
        return 2
    if args.action == "snapshot":
        m = b.snapshot()
        out = {"snapshot": m.id, "files": len(m.files), "bytes": m.total_bytes, "suspect": m.suspect, "notes": m.notes}
    elif args.action == "replicate":
        out = b.replicate()
    elif args.action == "verify":
        out = b.verify()
    elif args.action == "restore":
        out = vars(b.restore(args.snapshot, args.target))
    elif args.action == "drill":
        out = b.restore_drill()
    elif args.action == "prune":
        out = {"deleted": b.prune()}
    else:
        out = b.status()
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_intel(args) -> int:
    from .config import build, load_config
    from .intel.collectors import (FeedCollector, HttpFetcher, KEVCollector, NVDCollector, OSVCollector,
                                   enrich_from_nvd, load_fixture, merge_advisories, parse_feed, parse_kev,
                                   parse_nvd, parse_osv)
    cfg = load_config(args.config)
    aips = build(cfg)
    icfg = cfg.get("intel", {})
    sources = set(args.sources.split(",")) if args.sources else {"nvd", "kev", "osv", "feeds"}
    if args.offline:
        adv = merge_advisories(parse_nvd(json.loads(load_fixture("nvd_sample.json"))),
                               parse_kev(json.loads(load_fixture("kev_sample.json"))),
                               parse_osv(json.loads(load_fixture("osv_sample.json"))))
        reports = parse_feed(load_fixture("postmortems.xml"))
    else:
        fetcher = HttpFetcher(Path(getattr(aips, "data_dir", ".")) / "intel-cache")
        groups = []
        if "nvd" in sources:
            groups.append(NVDCollector(fetcher, os.environ.get(icfg.get("nvd_api_key_env", ""), None))
                          .recent(int(icfg.get("nvd_days", 7))))
        if "kev" in sources:
            groups.append(KEVCollector(fetcher).fetch())
        if "osv" in sources:
            groups.append(OSVCollector(fetcher).query_inventory(aips.inventory))
        adv = merge_advisories(*groups)
        if "nvd" in sources:
            enrich_from_nvd(adv, NVDCollector(fetcher, os.environ.get(icfg.get("nvd_api_key_env", ""), None)),
                            aips.inventory)
        reports = FeedCollector(fetcher, icfg.get("feeds", [])).fetch() if "feeds" in sources else []
    summary = aips.run_intel(adv, reports)
    rep = aips.tick()
    print(json.dumps({"summary": summary, "incidents_opened": rep.new_incidents}, indent=2))
    for i in rep.new_incidents:
        inc = aips.engine.incidents[i]
        print(f"  {inc.id} {inc.asset_id} {inc.signal} {inc.severity.name} -> {inc.status.value}")
    return 0


def cmd_gcp(args) -> int:
    from .integrations.gcp import GcpClient, GcpDiscovery, GcpError, default_token_provider
    from .integrations.gcp.client import IAM, LOGGING, MONITORING, SCC
    if args.verb == "baseline":
        from .config import build, load_config
        aips = build(load_config(args.config))
        obs = aips.collect(aips.clock.now())
        aips.last_obs = obs
        for asset in sorted(obs.configs):
            print(json.dumps(aips.capture_baseline(asset, args.approved_by)))
        return 0
    if not args.project:
        print("--project is required", file=sys.stderr)
        return 2
    tokens = default_token_provider()
    c = GcpClient(args.project, tokens)
    if args.verb == "check":
        try:
            tokens.token()
            print(f"OK    credentials via {tokens.used}")
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL  credentials: {exc}")
            return 1
        probes = [
            ("Compute Engine (VMs)", lambda: c.get(f"{c.compute}/aggregated/instances", maxResults=1)),
            ("Compute Engine (firewalls)", lambda: c.get(f"{c.compute}/global/firewalls", maxResults=1)),
            ("Cloud Monitoring", lambda: c.get(f"{MONITORING}/projects/{c.project}/metricDescriptors", pageSize=1)),
            ("Cloud Logging (audit logs)", lambda: c.post(f"{LOGGING}/entries:list",
                                                          {"resourceNames": [f"projects/{c.project}"], "pageSize": 1})),
            ("IAM (service accounts)", lambda: c.get(f"{IAM}/projects/{c.project}/serviceAccounts", pageSize=1)),
            ("Security Command Center", lambda: c.get(
                f"{SCC}/projects/{c.project}/sources/-/locations/global/findings", pageSize=1)),
        ]
        ok = True
        for name, fn in probes:
            try:
                fn()
                print(f"OK    {name}")
            except GcpError as exc:
                ok = ok and name == "Security Command Center"    # SCC is optional
                print(f"{'WARN' if name == 'Security Command Center' else 'FAIL'}  {name}: {exc}")
        return 0 if ok else 1
    topo = GcpDiscovery(c).topology()
    inv = GcpDiscovery.inventory(topo)
    print(f"{len(topo.instances)} VM(s), {len(topo.migs)} MIG(s), {len(topo.firewalls)} firewall rule(s), "
          f"{len(topo.service_accounts)} service account(s)")
    for a in inv:
        print(f"  {a.kind:8s} {a.id:32s} exposed ports: {a.allowed_ports or '-'}")
    if args.out:
        Path(args.out).write_text(GcpDiscovery.to_toml(inv), encoding="utf-8")
        print(f"inventory written to {args.out}")
    return 0


def cmd_experience(args) -> int:
    from .experience.store import ExperienceStore
    if not Path(args.db).exists():
        print(f"no experience database at {args.db}", file=sys.stderr)
        return 2
    st = ExperienceStore(args.db)
    try:
        s = st.summary()
        print(f"{s['episodes']} episodes, {s['incidents']} incidents, {s['runs']} run(s)  [{s['path']}]")
        print("outcomes:", ", ".join(f"{k}={v}" for k, v in s["outcomes"].items()) or "-")
        signals = [args.signal] if args.signal else list(s["top_signals"])
        for sig in signals:
            stats = st.strategy_stats(sig, args.asset)
            if not stats:
                continue
            print(f"\n{sig}")
            print(f"  {'strategy':24s} {'trials':>6s} {'success':>8s} {'reward':>7s} {'mean TTR':>9s}")
            for name, v in sorted(stats.items(), key=lambda kv: -kv[1]["mean_reward"]):
                ttr = f"{v['mean_ttr_s']:.0f}s" if v["mean_ttr_s"] is not None else "-"
                print(f"  {name:24s} {v['trials']:6.0f} {v['successes']:8.0f} {v['mean_reward']:7.2f} {ttr:>9s}")
    finally:
        st.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aips", description="Autonomous Infrastructure Protection System")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run simulated end-to-end scenarios")
    d.add_argument("--scenario", default="all")
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--verbose", "-v", action="store_true")
    d.add_argument("--json")
    d.set_defaults(fn=cmd_demo)

    sub.add_parser("scenarios", help="list scenarios").set_defaults(fn=cmd_scenarios)

    b = sub.add_parser("bench", help="benchmark scenarios across seeds")
    b.add_argument("--seeds", default="1-10")
    b.add_argument("--scenario")
    b.add_argument("--json")
    b.set_defaults(fn=cmd_bench)

    r = sub.add_parser("run", help="run AIPS against real infrastructure from a config file")
    r.add_argument("--config", required=True)
    r.add_argument("--once", action="store_true")
    r.add_argument("--ticks", type=int, default=0, help="stop after N cycles (0 = run until interrupted)")
    r.add_argument("--tick-seconds", type=float, default=0, help="override [aips] tick_seconds")
    r.add_argument("--report", help="write a JSON report of incidents and decisions on exit")
    r.add_argument("--no-api", action="store_true")
    r.set_defaults(fn=cmd_run)

    a = sub.add_parser("audit", help="audit ledger tools")
    a.add_argument("verb", choices=["verify"])
    a.add_argument("file")
    a.add_argument("--key-env")
    a.set_defaults(fn=cmd_audit)

    bk = sub.add_parser("backup", help="backup operations")
    bk.add_argument("action", choices=["snapshot", "replicate", "verify", "restore", "drill", "prune", "status"])
    bk.add_argument("--config", required=True)
    bk.add_argument("--snapshot", default="latest_clean")
    bk.add_argument("--target")
    bk.set_defaults(fn=cmd_backup)

    it = sub.add_parser("intel", help="assess public intelligence against the inventory")
    it.add_argument("verb", choices=["assess"])
    it.add_argument("--config", required=True)
    it.add_argument("--offline", action="store_true", help="use bundled fixtures instead of the network")
    it.add_argument("--sources")
    it.set_defaults(fn=cmd_intel)

    g = sub.add_parser("gcp", help="Google Cloud: check access, discover a project, record firewall baselines")
    g.add_argument("verb", choices=["check", "discover", "baseline"])
    g.add_argument("--project")
    g.add_argument("--out", help="discover: write the inventory TOML here")
    g.add_argument("--config", help="baseline: AIPS config with a [gcp] section")
    g.add_argument("--approved-by", default="operator", help="baseline: who approved this known-good state")
    g.set_defaults(fn=cmd_gcp)

    ex = sub.add_parser("experience", help="show what AIPS has learned (persistent history)")
    ex.add_argument("--db", required=True, help="path to experience.db (in [aips] data_dir by default)")
    ex.add_argument("--signal")
    ex.add_argument("--asset")
    ex.set_defaults(fn=cmd_experience)

    sub.add_parser("version").set_defaults(fn=lambda _a: print(__version__) or 0)

    args = p.parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
