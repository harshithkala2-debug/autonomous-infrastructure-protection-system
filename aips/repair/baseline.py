"""Record of the infrastructure's initial design / known working state.

The repair system compares what it observes with this record to identify the
change associated with a malfunction (concept section 5, steps 2-3).
Baselines are only (re)captured through an explicit, audited call - never
implicitly from whatever state happens to be running - so that a compromised
configuration cannot silently become the new "known good".
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SECURITY_SENSITIVE_KEYS = ("tls", "ssl", "auth", "password", "firewall", "public", "debug", "cors",
                           "admin", "acl", "encryption", "mfa", "allow", "secret", "token", "cipher")


@dataclass
class Baseline:
    asset_id: str
    config: dict[str, Any]
    open_ports: list[int] = field(default_factory=list)
    software: dict[str, str] = field(default_factory=dict)
    captured_at: float = 0.0
    approved_by: str = "system"
    version: int = 1


@dataclass
class Diff:
    path: str
    expected: Any
    actual: Any
    change: str      # modified | added | removed

    @property
    def security_sensitive(self) -> bool:
        p = self.path.lower()
        return any(k in p for k in SECURITY_SENSITIVE_KEYS)


_MISSING = object()


def diff_values(expected: Any, actual: Any, path: str = "") -> list[Diff]:
    if isinstance(expected, dict) and isinstance(actual, dict):
        out: list[Diff] = []
        for k in sorted(set(expected) | set(actual), key=str):
            sub = f"{path}.{k}" if path else str(k)
            e, a = expected.get(k, _MISSING), actual.get(k, _MISSING)
            if e is _MISSING:
                out.append(Diff(sub, None, a, "added"))
            elif a is _MISSING:
                out.append(Diff(sub, e, None, "removed"))
            else:
                out.extend(diff_values(e, a, sub))
        return out
    if expected != actual:
        return [Diff(path or "$", expected, actual, "modified")]
    return []


class DesiredStateStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._baselines: dict[str, Baseline] = {}
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            self.load()

    def capture(self, asset_id: str, config: dict[str, Any], open_ports: list[int] | None = None,
                software: dict[str, str] | None = None, at: float = 0.0, approved_by: str = "system") -> Baseline:
        with self._lock:
            prev = self._baselines.get(asset_id)
            b = Baseline(asset_id, json.loads(json.dumps(config)), sorted(open_ports or []), dict(software or {}),
                         at, approved_by, (prev.version + 1) if prev else 1)
            self._baselines[asset_id] = b
        self.save()
        return b

    def get(self, asset_id: str) -> Baseline | None:
        return self._baselines.get(asset_id)

    def all(self) -> list[Baseline]:
        return list(self._baselines.values())

    def compare_config(self, asset_id: str, observed: dict[str, Any]) -> list[Diff]:
        b = self._baselines.get(asset_id)
        if b is None:
            return []
        return diff_values(b.config, observed)

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: asdict(v) for k, v in self._baselines.items()}, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def load(self) -> None:
        assert self.path is not None
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self._baselines = {k: Baseline(**v) for k, v in data.items()}
