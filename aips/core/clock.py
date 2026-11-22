"""Injectable clocks so that the same code runs in real time and in simulation."""

from __future__ import annotations

import threading
import time


class Clock:
    def now(self) -> float:  # pragma: no cover - interface
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> float:
        return time.time()


class ManualClock(Clock):
    """Deterministic clock advanced explicitly by the simulator or tests."""

    def __init__(self, start: float = 1_700_000_000.0):
        self._t = float(start)
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return self._t

    def advance(self, seconds: float) -> float:
        with self._lock:
            self._t += float(seconds)
            return self._t

    def set(self, t: float) -> None:
        with self._lock:
            self._t = float(t)
