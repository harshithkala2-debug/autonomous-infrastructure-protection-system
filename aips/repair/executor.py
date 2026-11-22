"""Action dispatch: the only path from a decision to a change in infrastructure.

``ActionDispatcher`` routes each authorised ``ActionRequest`` to the component
that owns it:

* ``traffic.*``  -> ``TrafficController`` (the two valves)
* ``identity.*`` -> ``IdentityGuard``
* ``backup.*``   -> ``BackupManager``
* ``notify.*``   -> ``Notifier``
* everything else -> the configured ``InfrastructureAdapter``

Adapters provided:

* ``CommandAdapter`` - runs operator-defined, allow-listed command templates
  (``systemctl``, ``kubectl``, ``terraform``, cloud CLIs ...) without a shell,
  with strict argument validation, timeouts and optional rollback templates.
* ``RecordingAdapter`` - records calls and succeeds; for dry runs and tests.
* ``aips.sim.environment.SimulatedInfrastructure`` - simulator.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from ..core.models import ActionRequest, ActionResult

log = logging.getLogger("aips.executor")

_SAFE_ARG = re.compile(r"^[A-Za-z0-9_.:@/=+,-]{1,256}$")


class InfrastructureAdapter:
    name = "adapter"

    def execute(self, req: ActionRequest) -> ActionResult:  # pragma: no cover - interface
        raise NotImplementedError

    def rollback(self, result: ActionResult) -> ActionResult:
        return ActionResult(result.action_id, result.kind, result.target, False, "rollback not supported")

    def health(self, asset_id: str) -> bool | None:
        return None


class RecordingAdapter(InfrastructureAdapter):
    name = "recording"

    def __init__(self) -> None:
        self.calls: list[ActionRequest] = []

    def execute(self, req: ActionRequest) -> ActionResult:
        self.calls.append(req)
        return ActionResult(req.id, req.kind, req.target, True, "recorded", rollback={"undo": req.kind})

    def rollback(self, result: ActionResult) -> ActionResult:
        return ActionResult(result.action_id, result.kind + ".rollback", result.target, True, "recorded rollback")


@dataclass
class CommandTemplate:
    argv: list[str]
    rollback_argv: list[str] | None = None
    timeout_s: float = 120.0


class CommandAdapter(InfrastructureAdapter):
    """Executes allow-listed command templates. Example (TOML)::

        [adapter.commands."service.restart"]
        argv = ["systemctl", "restart", "{target}"]

        [adapter.commands."service.scale_out"]
        argv = ["kubectl", "scale", "deployment/{target}", "--replicas={replicas}"]

    Placeholders are filled from ``target`` and ``params``; every substituted
    value must match a conservative character allow-list, so neither a
    finding nor a compromised telemetry source can inject arguments.
    """

    name = "command"

    def __init__(self, templates: dict[str, CommandTemplate],
                 runner: Callable[..., subprocess.CompletedProcess] | None = None):
        self.templates = templates
        self.runner = runner or subprocess.run

    @classmethod
    def from_config(cls, d: dict[str, Any]) -> "CommandAdapter":
        return cls({k: CommandTemplate(list(v["argv"]), v.get("rollback_argv"), float(v.get("timeout_s", 120)))
                    for k, v in d.items()})

    @staticmethod
    def render(argv: list[str], values: dict[str, Any]) -> list[str]:
        out = []
        for part in argv:
            def sub(m: re.Match) -> str:
                key = m.group(1)
                if key not in values:
                    raise ValueError(f"template placeholder '{key}' has no value")
                val = str(values[key])
                if not _SAFE_ARG.match(val):
                    raise ValueError(f"unsafe value for '{key}': {val!r}")
                return val
            out.append(re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", sub, part))
        return out

    def _run(self, req_id: str, kind: str, target: str, argv: list[str], timeout: float) -> ActionResult:
        t0 = time.time()
        try:
            cp = self.runner(argv, capture_output=True, text=True, timeout=timeout, check=False, shell=False)
            ok = cp.returncode == 0
            detail = (cp.stdout or cp.stderr or "").strip()[-500:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        return ActionResult(req_id, kind, target, ok, detail, started_at=t0, finished_at=time.time())

    def execute(self, req: ActionRequest) -> ActionResult:
        tpl = self.templates.get(req.kind)
        if tpl is None:
            return ActionResult(req.id, req.kind, req.target, False, f"no command template for {req.kind}")
        values = {"target": req.target, **{k: v for k, v in req.params.items() if not isinstance(v, (list, dict))}}
        try:
            argv = self.render(tpl.argv, values)
        except ValueError as exc:
            return ActionResult(req.id, req.kind, req.target, False, f"refused: {exc}")
        res = self._run(req.id, req.kind, req.target, argv, tpl.timeout_s)
        if res.success and tpl.rollback_argv:
            res.rollback = {"argv": self.render(tpl.rollback_argv, values), "timeout": tpl.timeout_s}
        return res

    def rollback(self, result: ActionResult) -> ActionResult:
        if not result.rollback or "argv" not in result.rollback:
            return super().rollback(result)
        return self._run(result.action_id, result.kind + ".rollback", result.target, result.rollback["argv"],
                         result.rollback.get("timeout", 120))


class Notifier:
    """Fans notifications out to the log, an in-memory outbox and optional webhooks."""

    def __init__(self, webhooks: list[str] | None = None, timeout: float = 5.0):
        self.webhooks = webhooks or []
        self.timeout = timeout
        self.outbox: list[dict[str, Any]] = []

    def send(self, subject: str, body: str, severity: str = "info", data: dict | None = None) -> bool:
        msg = {"subject": subject, "body": body, "severity": severity, "data": data or {}, "ts": time.time()}
        self.outbox.append(msg)
        log.warning("NOTIFY [%s] %s - %s", severity, subject, body)
        ok = True
        for url in self.webhooks:
            if not url.startswith("https://"):
                ok = False
                continue
            try:
                req = urllib.request.Request(url, data=json.dumps(msg).encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=self.timeout).close()  # noqa: S310 - https enforced
            except OSError as exc:
                log.error("webhook delivery failed: %s", exc)
                ok = False
        return ok


Handler = Callable[[ActionRequest], tuple[bool, str, dict[str, Any] | None]]


@dataclass
class ActionDispatcher:
    adapter: InfrastructureAdapter
    now: Callable[[], float]
    handlers: dict[str, Handler] = field(default_factory=dict)          # exact kind -> handler
    prefix_handlers: dict[str, Handler] = field(default_factory=dict)   # "traffic." -> handler
    rollback_handlers: dict[str, Callable[[ActionResult], tuple[bool, str]]] = field(default_factory=dict)
    dry_run: bool = False

    def register(self, kind: str, handler: Handler) -> None:
        if kind.endswith("."):
            self.prefix_handlers[kind] = handler
        else:
            self.handlers[kind] = handler

    def _handler(self, kind: str) -> Handler | None:
        if kind in self.handlers:
            return self.handlers[kind]
        for p, h in self.prefix_handlers.items():
            if kind.startswith(p):
                return h
        return None

    def execute(self, req: ActionRequest) -> ActionResult:
        t0 = self.now()
        if self.dry_run and not req.kind.startswith("notify."):
            return ActionResult(req.id, req.kind, req.target, True, "dry-run: not executed", dry_run=True,
                                started_at=t0, finished_at=t0)
        h = self._handler(req.kind)
        try:
            if h is not None:
                ok, detail, rb = h(req)
                res = ActionResult(req.id, req.kind, req.target, ok, detail, rollback=rb)
            else:
                res = self.adapter.execute(req)
        except Exception as exc:  # noqa: BLE001 - an executor failure is an action failure, not a crash
            res = ActionResult(req.id, req.kind, req.target, False, f"{type(exc).__name__}: {exc}")
        res.started_at, res.finished_at = t0, self.now()
        return res

    def rollback(self, result: ActionResult) -> ActionResult:
        if result.dry_run:
            return ActionResult(result.action_id, result.kind + ".rollback", result.target, True, "dry-run")
        rh = next((h for p, h in self.rollback_handlers.items() if result.kind.startswith(p)), None)
        if rh:
            ok, detail = rh(result)
            return ActionResult(result.action_id, result.kind + ".rollback", result.target, ok, detail)
        if self._handler(result.kind) is not None:
            return ActionResult(result.action_id, result.kind + ".rollback", result.target, False,
                                "internal action has no rollback")
        return self.adapter.rollback(result)
