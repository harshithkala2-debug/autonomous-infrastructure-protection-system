"""Domain model shared by all levels and fleets.

Everything that moves between bots is one of these dataclasses, so each level
receives a well-defined, serialisable body of evidence.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import threading
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum, IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | int | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        return cls[str(value).strip().upper()]

    def bump(self, steps: int = 1) -> "Severity":
        return Severity(max(0, min(4, int(self) + steps)))


class Category(str, Enum):
    AVAILABILITY = "availability"
    PERFORMANCE = "performance"
    CAPACITY = "capacity"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    IDENTITY = "identity"
    DATA_INTEGRITY = "data_integrity"
    VULNERABILITY = "vulnerability"


class Level(IntEnum):
    L1_DETECTION = 1
    L2_EVALUATION = 2
    L3_DECISION = 3
    HUMAN = 4


class Disposition(str, Enum):
    DISMISS = "dismiss"          # judged a false alarm
    MONITOR = "monitor"          # real but not yet actionable; keep watching
    HANDLE = "handle"            # handled at Level 2 with low-risk actions
    ESCALATE = "escalate"        # sent to Level 3


class Risk(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class IncidentStatus(str, Enum):
    OPEN = "open"
    MITIGATING = "mitigating"
    AWAITING_APPROVAL = "awaiting_approval"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    FAILED = "failed"            # automation exhausted; handed to humans
    DISMISSED = "dismissed"


ACTIVE_STATUSES = {
    IncidentStatus.OPEN,
    IncidentStatus.MITIGATING,
    IncidentStatus.AWAITING_APPROVAL,
    IncidentStatus.VERIFYING,
}


_counter = itertools.count(1)
_counter_lock = threading.Lock()


def new_id(prefix: str) -> str:
    """Short, monotonically increasing, process-unique identifier."""
    with _counter_lock:
        n = next(_counter)
    return f"{prefix}-{n:06d}"


def reset_ids() -> None:
    """Reset the id counter (used by deterministic simulations and tests)."""
    global _counter
    with _counter_lock:
        _counter = itertools.count(1)


@dataclass
class Evidence:
    kind: str                     # metric | config_diff | event | access | advisory | file_change ...
    source: str                   # producing bot / collector
    data: dict[str, Any]
    observed_at: float


@dataclass
class Finding:
    detector: str
    category: Category
    severity: Severity
    confidence: float
    asset_id: str
    title: str
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    created_at: float = 0.0
    signal: str = ""              # machine-readable signal type, e.g. "service_down", "disk_forecast"
    tags: dict[str, str] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("F"))
    route: list[int] = field(default_factory=list)   # levels the finding passed through

    @property
    def fingerprint(self) -> str:
        """Stable identity used for de-duplication and outcome learning."""
        raw = f"{self.detector}|{self.signal}|{self.asset_id}|{self.category.value}|{self.tags.get('key', '')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Verdict:
    """Level 2 output: the result of evaluating one correlated group of findings."""

    case_key: str
    asset_id: str
    category: Category
    signal: str
    disposition: Disposition
    severity: Severity
    confidence: float
    rationale: list[str]
    findings: list[Finding]
    root_cause_asset: str | None = None
    id: str = field(default_factory=lambda: new_id("V"))


@dataclass
class ActionRequest:
    kind: str                     # e.g. "service.restart", "identity.freeze"
    target: str                   # asset id, identity id, valve id ...
    params: dict[str, Any] = field(default_factory=dict)
    requested_by: Level = Level.L3_DECISION
    incident_id: str | None = None
    risk: Risk = Risk.LOW
    reversible: bool = True
    rationale: str = ""
    id: str = field(default_factory=lambda: new_id("A"))


@dataclass
class ActionResult:
    action_id: str
    kind: str
    target: str
    success: bool
    detail: str = ""
    dry_run: bool = False
    rollback: dict[str, Any] | None = None   # data needed to undo the action
    started_at: float = 0.0
    finished_at: float = 0.0


@dataclass
class TimelineEntry:
    at: float
    actor: str
    event: str
    detail: str = ""


@dataclass
class Incident:
    asset_id: str
    category: Category
    signal: str
    severity: Severity
    opened_at: float
    status: IncidentStatus = IncidentStatus.OPEN
    level: Level = Level.L3_DECISION
    playbook: str | None = None
    findings: list[str] = field(default_factory=list)
    actions: list[ActionResult] = field(default_factory=list)
    pending_approvals: list[str] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    attempts: int = 0
    resolved_at: float | None = None
    root_cause_asset: str | None = None
    verify_passes: int = 0
    id: str = field(default_factory=lambda: new_id("INC"))

    @property
    def key(self) -> str:
        return f"{self.asset_id}|{self.category.value}|{self.signal}"

    def log(self, at: float, actor: str, event: str, detail: str = "") -> None:
        self.timeline.append(TimelineEntry(at, actor, event, detail))

    @property
    def active(self) -> bool:
        return self.status in ACTIVE_STATUSES


def to_jsonable(obj: Any) -> Any:
    """Convert dataclasses / enums / sets recursively into JSON-friendly values."""
    if is_dataclass(obj) and not isinstance(obj, type):
        out = {k: to_jsonable(v) for k, v in asdict(obj).items()}
        if isinstance(obj, Finding):
            out["fingerprint"] = obj.fingerprint
        return out
    if isinstance(obj, Enum):
        return obj.value if not isinstance(obj, IntEnum) else obj.name
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in obj]
    return obj


def canonical_json(obj: Any) -> str:
    return json.dumps(to_jsonable(obj), sort_keys=True, separators=(",", ":"), default=str)
