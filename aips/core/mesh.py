"""Layer mesh: any layer can dynamically call any other layer.

The strict pipeline (L1 -> L2 -> L3) is only the *default* path. Real
decisions often need a layer to ask another for help:

* Level 2 is unsure            -> asks Level 1 for a fresh, targeted re-scan;
* Level 2 sees a recurring case -> asks the experience store for history;
* Level 3 is about to act       -> asks Level 1 whether the problem is still there;
* any fleet finds something severe -> calls Level 3 directly to escalate.

Each layer *registers capabilities* (named functions). Callers address them
as ``mesh.call(caller, target, capability, payload)``. The mesh provides:

* discovery (``capabilities()``) so layers need no hard-coded references;
* re-entrancy protection: a call already on the current call stack with the
  same target, capability and payload is refused (no A -> B -> A loops);
* a maximum call depth;
* per-capability statistics and a bounded log of recent calls;
* audit records for capabilities that change state (``mutating=True``).
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Callable

from .audit import AuditLedger


@dataclass
class Capability:
    layer: str
    name: str
    fn: Callable[[dict[str, Any]], Any]
    description: str = ""
    mutating: bool = False


@dataclass
class CallRecord:
    caller: str
    target: str
    capability: str
    ok: bool
    depth: int
    duration_ms: float
    summary: str = ""
    error: str = ""


@dataclass
class CallResult:
    ok: bool
    value: Any = None
    error: str = ""
    path: list[str] = field(default_factory=list)


class MeshError(Exception):
    pass


class LayerMesh:
    def __init__(self, audit: AuditLedger | None = None, max_depth: int = 4, log_size: int = 2000):
        self._caps: dict[tuple[str, str], Capability] = {}
        self._local = threading.local()
        self.audit = audit
        self.max_depth = max_depth
        self.log: deque[CallRecord] = deque(maxlen=log_size)
        self.stats: Counter = Counter()
        self.refused: Counter = Counter()

    # -- registration ------------------------------------------------------------
    def register(self, layer: str, name: str, fn: Callable[[dict[str, Any]], Any], description: str = "",
                 mutating: bool = False) -> None:
        self._caps[(layer, name)] = Capability(layer, name, fn, description, mutating)

    def capabilities(self, layer: str | None = None) -> list[dict[str, Any]]:
        return [{"layer": c.layer, "capability": c.name, "description": c.description, "mutating": c.mutating}
                for c in self._caps.values() if layer is None or c.layer == layer]

    def has(self, layer: str, name: str) -> bool:
        return (layer, name) in self._caps

    # -- calling -----------------------------------------------------------------
    def _stack(self) -> list[tuple[str, str, str]]:
        if not hasattr(self._local, "stack"):
            self._local.stack = []
        return self._local.stack

    @staticmethod
    def _key(payload: dict[str, Any] | None) -> str:
        try:
            return json.dumps(payload or {}, sort_keys=True, default=str)[:300]
        except (TypeError, ValueError):
            return repr(payload)[:300]

    def call(self, caller: str, target: str, capability: str, payload: dict[str, Any] | None = None) -> CallResult:
        cap = self._caps.get((target, capability))
        stack = self._stack()
        path = [f"{t}.{c}" for t, c, _ in stack] + [f"{target}.{capability}"]
        if cap is None:
            self.refused["unknown"] += 1
            return CallResult(False, error=f"{target}.{capability} is not registered", path=path)
        frame = (target, capability, self._key(payload))
        if frame in stack:
            self.refused["loop"] += 1
            return CallResult(False, error=f"refused re-entrant call {' -> '.join(path)}", path=path)
        if len(stack) >= self.max_depth:
            self.refused["depth"] += 1
            return CallResult(False, error=f"call depth {len(stack)} exceeds {self.max_depth}", path=path)
        stack.append(frame)
        t0 = time.perf_counter()
        try:
            value = cap.fn(dict(payload or {}))
            ok, err = True, ""
        except Exception as exc:  # noqa: BLE001 - a failing capability is reported, never propagated
            value, ok, err = None, False, f"{type(exc).__name__}: {exc}"
        finally:
            stack.pop()
        ms = (time.perf_counter() - t0) * 1000
        self.stats[f"{target}.{capability}"] += 1
        summary = _summarise(value)
        self.log.append(CallRecord(caller, target, capability, ok, len(stack), round(ms, 3), summary, err))
        if cap.mutating and self.audit is not None:
            self.audit.append(caller, "mesh.call", {"target": target, "capability": capability,
                                                    "payload": self._key(payload), "ok": ok, "error": err})
        return CallResult(ok, value, err, path)

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return [vars(r) for r in list(self.log)[-limit:]]

    def snapshot(self) -> dict[str, Any]:
        return {"capabilities": len(self._caps), "calls": dict(self.stats), "refused": dict(self.refused)}


def _summarise(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={value[k]}" for k in list(value)[:4])[:160]
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    return str(value)[:160]
