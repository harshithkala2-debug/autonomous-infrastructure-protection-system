"""Traffic-control valves (concept section 5).

Every protected component has **two valves**:

* **Ingress valve** - limits the external request stream *into* the component
  (clients, load balancer, API gateway).
* **Internal valve** - limits internal data streams the component must
  process (queue consumers, replication, batch jobs, inter-service calls).

A valve has a *position* between 0.0 (shut) and 1.0 (fully open). The
admitted rate is ``capacity_rps * position``, enforced by a token bucket.
Below certain positions lower-priority traffic is shed first:

=============  ==========  ===========================================
position       mode        admitted priorities
=============  ==========  ===========================================
1.0            OPEN        all
0.5 - <1.0     THROTTLED   all, rate-limited
0.2 - <0.5     RESTRICTED  CRITICAL and NORMAL (BULK shed)
>0 - <0.2      CRITICAL    CRITICAL only
0              SHUT        none (only via isolation / human)
=============  ==========  ===========================================

Relationship to repair: a playbook closes valves *before* repairing
(reducing load on the affected part), and after verification the controller
re-opens them with additive-increase / multiplicative-decrease ramping: +step
per healthy cycle, halve on regression. Autonomous throttles never go below
``min_autonomous_position`` so a bot cannot black-hole a service by itself.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Callable

VALVE_KINDS = ("ingress", "internal")


class Priority(IntEnum):
    CRITICAL = 0
    NORMAL = 1
    BULK = 2


class ValveMode(str, Enum):
    OPEN = "open"
    THROTTLED = "throttled"
    RESTRICTED = "restricted"
    CRITICAL_ONLY = "critical_only"
    SHUT = "shut"


@dataclass
class Valve:
    asset_id: str
    kind: str
    capacity_rps: float = 1000.0
    position: float = 1.0
    target: float = 1.0
    ramping: bool = False
    reason: str = ""
    tokens: float = 0.0
    last_refill: float | None = None
    admitted: int = 0
    rejected: int = 0
    history: list[tuple[float, float, str]] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.asset_id}:{self.kind}"

    @property
    def mode(self) -> ValveMode:
        p = self.position
        if p >= 0.999:
            return ValveMode.OPEN
        if p >= 0.5:
            return ValveMode.THROTTLED
        if p >= 0.2:
            return ValveMode.RESTRICTED
        if p > 0:
            return ValveMode.CRITICAL_ONLY
        return ValveMode.SHUT

    def admits_priority(self, prio: Priority) -> bool:
        m = self.mode
        if m in (ValveMode.OPEN, ValveMode.THROTTLED):
            return True
        if m == ValveMode.RESTRICTED:
            return prio <= Priority.NORMAL
        if m == ValveMode.CRITICAL_ONLY:
            return prio == Priority.CRITICAL
        return False

    def admit(self, now: float, prio: Priority = Priority.NORMAL, cost: float = 1.0) -> bool:
        if not self.admits_priority(prio):
            self.rejected += 1
            return False
        rate = self.capacity_rps * self.position
        burst = max(1.0, rate)          # one second of burst
        if self.last_refill is None:
            self.tokens, self.last_refill = burst, now
        else:
            self.tokens = min(burst, self.tokens + (now - self.last_refill) * rate)
            self.last_refill = now
        if prio == Priority.CRITICAL and self.position > 0:
            self.admitted += 1          # critical traffic is never rate-limited while the valve is open at all
            return True
        if self.tokens >= cost:
            self.tokens -= cost
            self.admitted += 1
            return True
        self.rejected += 1
        return False


@dataclass
class ValveConfig:
    ramp_step: float = 0.25
    backoff_factor: float = 0.5
    min_autonomous_position: float = 0.1
    default_capacity_rps: float = 1000.0


class TrafficController:
    def __init__(self, config: ValveConfig | None = None,
                 on_change: Callable[[str, str, float], None] | None = None):
        self.config = config or ValveConfig()
        self.on_change = on_change
        self._valves: dict[tuple[str, str], Valve] = {}
        self._lock = threading.RLock()

    def valve(self, asset_id: str, kind: str) -> Valve:
        if kind not in VALVE_KINDS:
            raise ValueError(f"unknown valve kind '{kind}' (expected one of {VALVE_KINDS})")
        with self._lock:
            key = (asset_id, kind)
            if key not in self._valves:
                self._valves[key] = Valve(asset_id, kind, self.config.default_capacity_rps)
            return self._valves[key]

    def valves(self) -> list[Valve]:
        return list(self._valves.values())

    def position(self, asset_id: str, kind: str) -> float:
        v = self._valves.get((asset_id, kind))
        return v.position if v else 1.0

    def _set(self, v: Valve, pos: float, reason: str, now: float) -> None:
        pos = round(max(0.0, min(1.0, pos)), 4)
        if pos == v.position:
            return
        v.position = pos
        v.reason = reason
        v.history.append((now, pos, reason))
        if self.on_change:
            self.on_change(v.asset_id, v.kind, pos)

    def throttle(self, asset_id: str, kind: str, position: float, reason: str, now: float,
                 autonomous: bool = True) -> Valve:
        kinds = VALVE_KINDS if kind == "both" else (kind,)
        v = None
        with self._lock:
            for k in kinds:
                v = self.valve(asset_id, k)
                floor = self.config.min_autonomous_position if autonomous else 0.0
                new = max(floor, min(position, v.position)) if v.ramping is False else max(floor, position)
                v.ramping, v.target = False, new
                self._set(v, new, reason, now)
        assert v is not None
        return v

    def restrict(self, asset_id: str, reason: str, now: float) -> None:
        """Admit only critical traffic on both valves."""
        for k in VALVE_KINDS:
            self.throttle(asset_id, k, self.config.min_autonomous_position, reason, now)

    def release(self, asset_id: str, reason: str, now: float, kind: str = "both") -> None:
        kinds = VALVE_KINDS if kind == "both" else (kind,)
        with self._lock:
            for k in kinds:
                v = self._valves.get((asset_id, k))
                if v and v.position < 1.0:
                    v.ramping, v.target, v.reason = True, 1.0, reason

    def tick(self, now: float, healthy: Callable[[str], bool]) -> list[tuple[str, float]]:
        """Advance ramping valves; returns list of (valve_id, new_position)."""
        changed = []
        with self._lock:
            for v in self._valves.values():
                if not v.ramping:
                    continue
                if healthy(v.asset_id):
                    new = min(v.target, v.position + self.config.ramp_step)
                    self._set(v, new, "ramp: healthy", now)
                else:
                    new = max(self.config.min_autonomous_position, v.position * self.config.backoff_factor)
                    self._set(v, new, "ramp: regression - backing off", now)
                changed.append((v.id, v.position))
                if v.position >= v.target:
                    v.ramping = False
        return changed

    def snapshot(self) -> list[dict]:
        return [{"id": v.id, "asset": v.asset_id, "kind": v.kind, "position": v.position, "mode": v.mode.value,
                 "ramping": v.ramping, "reason": v.reason, "admitted": v.admitted, "rejected": v.rejected}
                for v in self._valves.values()]
