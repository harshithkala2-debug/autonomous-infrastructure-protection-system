"""``aips web ...`` and ``aips sandbox ...`` commands."""

from __future__ import annotations

import getpass
import json
import os
import sys
import time
import urllib.request
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("AIPS_WEB_HOME") or Path.home() / ".aips-web")


def _passphrase(args, prompt: str = "Human passphrase: ", confirm: bool = False) -> str:
    if getattr(args, "passphrase_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    p = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat it: ") != p:
        raise SystemExit("passphrases did not match")
    return p


def _local(url: str, path: str, body: dict | None = None):
    req = urllib.request.Request(url.rstrip("/") + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def cmd_web(args) -> int:
    from .human import HumanLock
    from .trust import Credential, TrustDomain

    h = Path(args.home) if args.home else home()
    dom_path, human_path = h / "domain.json", h / "human.json"

    if args.verb == "init":
        if dom_path.exists() and not args.force:
            print(f"a trust domain already exists in {h} (use --force to replace it)")
            return 1
        d = TrustDomain.create(args.domain, dom_path)
        recovery = HumanLock(human_path).setup(_passphrase(args, "Choose a human passphrase (10+ chars): ", True))
        print(f"trust domain '{d.domain}' created in {h}")
        print(f"RECOVERY CODE (write it down, it is shown once): {recovery}")
        return 0
    if args.verb == "demo":
        from .demo import run
        report = run(print)
        if args.json:
            Path(args.json).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            print(f"evidence written to {args.json}")
        return 0 if report["passed"] == report["total"] else 1
    if args.verb in ("issue", "revoke", "members", "hub"):
        if not dom_path.exists():
            print(f"no trust domain in {h}; run: aips web init --domain NAME")
            return 1
        d = TrustDomain.load(dom_path)
        if args.verb == "issue":
            cred = d.issue(args.node, [r.strip() for r in args.roles.split(",") if r.strip()], args.hub or "")
            out = Path(args.out or f"{args.node}.credential.json")
            cred.save(out)
            print(f"credential for {args.node} ({', '.join(cred.roles)}) written to {out}; copy it to that machine "
                  "privately and delete it here")
            return 0
        if args.verb == "revoke":
            print("revoked" if d.revoke(args.node) else "no such node")
            return 0
        if args.verb == "members":
            for m in d.members.values():
                print(f"{m.node:20} {','.join(m.roles):24} epoch={m.epoch} {'REVOKED' if m.revoked else ''}")
            return 0
        from .hub import WebHub, make_server
        hub = WebHub(d, h, HumanLock(human_path))
        if not args.locked:
            hub.human.unlock(_passphrase(args, "Unlock the hub (human passphrase): "))
        srv = make_server(hub, args.host, args.port, args.tls_cert, args.tls_key)
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"AIPS web hub for '{d.domain}' on {args.host}:{srv.server_address[1]} "
              f"({'TLS' if args.tls_cert else 'no TLS: use only on a trusted network or behind a TLS proxy'}); "
              f"approvals {'enabled' if hub.human.unlocked else 'disabled (locked)'}")
        try:
            while True:
                time.sleep(5)
                hub.tick()
        except KeyboardInterrupt:
            srv.shutdown()
        return 0
    if args.verb == "node":
        from .node import WebNode
        cred = Credential.load(args.cred)
        node = WebNode(cred, args.state or h / "node" / cred.node, args.hub, args.cafile)
        print(f"node {cred.node} ({', '.join(cred.roles)}) joining {args.hub or cred.hub}")
        node.run_forever(args.interval)
        return 0
    if args.verb == "status":
        from .node import WebClient
        print(json.dumps(WebClient(Credential.load(args.cred), args.hub).status(), indent=2, default=str))
        return 0
    if args.verb == "approvals":
        code, body = _local(args.hub, "/web/approvals")
        print(json.dumps(body, indent=2))
        return 0 if code == 200 else 1
    if args.verb == "approve":
        code, pending = _local(args.hub, "/web/approvals")
        req = next((a for a in pending if a["id"] == args.request_id), None) if code == 200 else None
        if req is None:
            print("no such pending request")
            return 1
        print(f"approve {req['kind']}: {req['action']}")
        token = HumanLock(human_path).approve(_passphrase(args), req["id"], req["action"])
        code, body = _local(args.hub, "/web/approve", {"request_id": req["id"], "token": token})
        print(json.dumps(body, indent=2))
        return 0 if code == 200 else 1
    if args.verb == "reset-passphrase":
        lock = HumanLock(human_path)
        code = input("Recovery code: ").strip()
        print("new RECOVERY CODE:", lock.reset_with_recovery(code, _passphrase(args, "New passphrase: ", True)))
        return 0
    return 2


def cmd_sandbox(args) -> int:
    from ..agents.guard import AgentGuard
    from ..agents.sandbox import HybridSandbox, LocalSandbox, SandboxLimits
    from ..ml import default_risk_model

    lim = SandboxLimits(timeout_s=args.timeout, memory_mb=args.memory_mb, network=args.network)
    remote = None
    if args.remote:
        from .node import WebClient
        from .trust import Credential
        from ..agents.sandbox import SandboxResult
        client = WebClient(Credential.load(args.remote))

        def remote(req):
            return SandboxResult.from_dict(client.sandbox(req["command"], req["files"], timeout=args.timeout + 30))

    guard = AgentGuard()
    hy = HybridSandbox(LocalSandbox(limits=lim), guard, remote, default_risk_model(),
                       approver=(lambda _cid, cmd: input(f"approve '{cmd}'? [y/N] ").lower() == "y")
                       if args.ask else None)
    command = " ".join(args.command)
    out = hy.run(args.agent, command, args.workspace, limits=lim)
    print(f"verdict {out.verdict.upper()} (risk {out.risk:.2f}, learned {out.learned_risk}) -> tier {out.tier}")
    for r in out.reasons[:6]:
        print("  ", r)
    if out.result is None:
        print("not run" + (" (needs approval: re-run with --ask)" if out.approval_needed else ""))
        return 1
    res = out.result
    print("isolation:", "; ".join(res.isolation))
    print(f"exit {res.exit_code}{' (timed out)' if res.timed_out else ''} in {res.duration_s}s on "
          f"{res.node or 'this machine'}")
    if res.stdout:
        print("--- stdout\n" + res.stdout.rstrip())
    if res.stderr:
        print("--- stderr\n" + res.stderr.rstrip())
    if res.changed:
        print("changes (in the jail):", json.dumps(res.changed))
        if args.promote and args.workspace and res.tier == "local":
            print("promoted:", json.dumps(hy.promote(args.agent, res, args.workspace)))
    return 0 if res.ok else 1


def add_parsers(sub) -> None:
    w = sub.add_parser("web", help="the AIPS web: trust domain, hub (orchestrator), nodes, approvals")
    w.add_argument("verb", choices=["init", "issue", "revoke", "members", "hub", "node", "status", "approvals",
                                    "approve", "reset-passphrase", "demo"])
    w.add_argument("node", nargs="?", help="node name (issue / revoke)")
    w.add_argument("request_id", nargs="?", help="request id (approve)")
    w.add_argument("--home", help="state directory (default ~/.aips-web or AIPS_WEB_HOME)")
    w.add_argument("--domain", default="aips-web")
    w.add_argument("--roles", default="client", help="comma list: client,sandbox,storage,observer")
    w.add_argument("--hub", help="hub URL, e.g. https://hub.example:8443")
    w.add_argument("--out")
    w.add_argument("--cred", help="node credential file")
    w.add_argument("--cafile", help="CA bundle to trust the hub's TLS certificate")
    w.add_argument("--state")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8443)
    w.add_argument("--tls-cert")
    w.add_argument("--tls-key")
    w.add_argument("--locked", action="store_true", help="start the hub without unlocking approvals")
    w.add_argument("--interval", type=float, default=2.0)
    w.add_argument("--force", action="store_true")
    w.add_argument("--passphrase-stdin", action="store_true")
    w.add_argument("--json", help="demo: write the evidence report here")
    w.set_defaults(fn=_web_entry)

    s = sub.add_parser("sandbox", help="run a command in the hybrid sandbox (judged first, never in the real folder)")
    s.add_argument("command", nargs="+")
    s.add_argument("--workspace", help="folder to copy into the jail")
    s.add_argument("--agent", default="cli")
    s.add_argument("--timeout", type=float, default=60.0)
    s.add_argument("--memory-mb", type=int, default=512)
    s.add_argument("--network", action="store_true", help="do not set the dead proxy")
    s.add_argument("--remote", help="credential file: send risky commands to a sandbox node of the web")
    s.add_argument("--ask", action="store_true", help="prompt to approve commands that need a human")
    s.add_argument("--promote", action="store_true", help="copy changes back (checkpointed, revertable)")
    s.set_defaults(fn=cmd_sandbox)


def _web_entry(args) -> int:
    # "aips web approve ID": the positional after the verb lands in ``node``
    if args.verb == "approve" and args.request_id is None:
        args.request_id = args.node
    return cmd_web(args)
