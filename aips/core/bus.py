"""In-process publish/subscribe bus connecting the fleets.

Topics are dotted strings (``finding.l1``, ``incident.opened``). Subscribers
may use ``*`` as a trailing wildcard (``incident.*``) or ``#`` for everything.
A failing subscriber never breaks the publisher: its exception is captured in
a dead-letter list and reported through ``stats``.

The bus is synchronous by design: the orchestrator drives a deterministic
tick loop, which makes behaviour reproducible in tests and simulations. A
transport adapter (Kafka, NATS, Redis streams) can implement the same
``publish``/``subscribe`` interface for distributed deployments.
"""

from __future__ import annotations

import logging
import threading
import traceback
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable

log = logging.getLogger("aips.bus")

Handler = Callable[[str, Any], None]


@dataclass
class DeadLetter:
    topic: str
    handler: str
    error: str


class EventBus:
    def __init__(self, dead_letter_limit: int = 1000, history_limit: int = 5000):
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._lock = threading.RLock()
        self.dead_letters: deque[DeadLetter] = deque(maxlen=dead_letter_limit)
        self.history: deque[tuple[str, Any]] = deque(maxlen=history_limit)
        self.published: dict[str, int] = defaultdict(int)

    def subscribe(self, pattern: str, handler: Handler) -> Callable[[], None]:
        with self._lock:
            self._subs[pattern].append(handler)

        def unsubscribe() -> None:
            with self._lock:
                if handler in self._subs.get(pattern, []):
                    self._subs[pattern].remove(handler)

        return unsubscribe

    @staticmethod
    def matches(pattern: str, topic: str) -> bool:
        if pattern in ("#", "*"):
            return True
        if pattern.endswith(".*"):
            return topic.startswith(pattern[:-1]) or topic == pattern[:-2]
        return pattern == topic

    def publish(self, topic: str, payload: Any = None) -> int:
        with self._lock:
            handlers = [h for p, hs in self._subs.items() if self.matches(p, topic) for h in hs]
            self.history.append((topic, payload))
            self.published[topic] += 1
        delivered = 0
        for h in handlers:
            try:
                h(topic, payload)
                delivered += 1
            except Exception as exc:  # noqa: BLE001 - isolation is the point
                name = getattr(h, "__qualname__", repr(h))
                log.error("subscriber %s failed on %s: %s", name, topic, exc)
                self.dead_letters.append(DeadLetter(topic, name, "".join(traceback.format_exception_only(exc)).strip()))
        return delivered

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "topics": dict(self.published),
                "subscriptions": {p: len(hs) for p, hs in self._subs.items()},
                "dead_letters": len(self.dead_letters),
            }
