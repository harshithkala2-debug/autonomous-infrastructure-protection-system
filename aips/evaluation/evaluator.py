"""Level 2 evaluation bot.

Receives Level 1 findings and decides, per correlated *case*
(asset + category + signal), whether it is a false alarm, something to keep
watching, something Level 2 can handle with low-risk actions, or something
that must go to Level 3.

Evidence used (answers "what evidence each evaluation level receives"):

* every finding in the case within the correlation window,
* corroboration from *independent* detectors on the same asset,
* persistence (how many cycles the case has been observed),
* flapping behaviour,
* dependency graph: is an upstream dependency already impaired? (root cause),
* maintenance windows and operator suppressions,
* outcome memory: historical precision of the detector / fingerprint.
"""

from __future__ import annotations

import fnmatch
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..core.models import Category, Disposition, Finding, Severity, Verdict
from ..telemetry.inventory import Inventory
from .learning import OutcomeMemory


@dataclass
class EvaluatorConfig:
    dismiss_below: float = 0.30
    handle_min: float = 0.50
    escalate_min: float = 0.60
    low_severity_persistence: int = 3
    case_ttl_s: float = 180.0
    correlation_window_s: float = 300.0
    flap_limit: int = 4

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvaluatorConfig":
        c = cls()
        for k, v in d.items():
            if hasattr(c, k):
                setattr(c, k, type(getattr(c, k))(v))
        return c


@dataclass
class MaintenanceWindow:
    asset_pattern: str
    start: float
    end: float
    reason: str = ""


@dataclass
class Case:
    key: str
    asset_id: str
    category: Category
    signal: str
    first_seen: float
    last_seen: float
    findings: deque = field(default_factory=lambda: deque(maxlen=50))
    occurrences: int = 0
    reappearances: deque = field(default_factory=lambda: deque(maxlen=20))
    max_disposition: Disposition = Disposition.MONITOR
    absent: bool = False


def _never(_asset_id: str) -> bool:
    return False


_RANK = {Disposition.DISMISS: 0, Disposition.MONITOR: 1, Disposition.HANDLE: 2, Disposition.ESCALATE: 3}


class Level2Evaluator:
    name = "l2.evaluator"

    def __init__(self, inventory: Inventory, memory: OutcomeMemory | None = None,
                 config: EvaluatorConfig | None = None, l2_signals: Iterable[str] = ()):
        self.inventory = inventory
        self.memory = memory or OutcomeMemory()
        self.config = config or EvaluatorConfig()
        self.l2_signals = list(l2_signals)
        self.cases: dict[str, Case] = {}
        self.maintenance: list[MaintenanceWindow] = []
        self.suppressions: set[str] = set()       # fingerprints an operator marked benign
        self._recent_by_asset: dict[str, deque[Finding]] = defaultdict(lambda: deque(maxlen=200))
        self._impaired: dict[str, float] = {}
        self.under_mitigation: Callable[[str], bool] = _never
        # must exceed the anomaly detector's level-shift window (10) so a sustained new normal is absorbed,
        # while recurring, intermittent unexplained anomalies still reach a human
        self.anomaly_persistence = 12

    # -- operator controls ---------------------------------------------------
    def add_maintenance(self, w: MaintenanceWindow) -> None:
        self.maintenance.append(w)

    def suppress(self, fingerprint: str) -> None:
        self.suppressions.add(fingerprint)

    def in_maintenance(self, asset_id: str, now: float) -> MaintenanceWindow | None:
        for w in self.maintenance:
            if w.start <= now <= w.end and fnmatch.fnmatch(asset_id, w.asset_pattern):
                return w
        return None

    # -- context -------------------------------------------------------------
    def observe_context(self, findings: Iterable[Finding], now: float) -> None:
        """Record every finding (including ones that bypassed Level 2) for correlation."""
        for f in findings:
            self._recent_by_asset[f.asset_id].append(f)
            if f.category in (Category.AVAILABILITY, Category.CAPACITY) and f.severity >= Severity.MEDIUM:
                self._impaired[f.asset_id] = now

    def mark_impaired(self, asset_id: str, now: float) -> None:
        self._impaired[asset_id] = now

    def impaired(self, asset_id: str, now: float) -> bool:
        t = self._impaired.get(asset_id)
        return t is not None and now - t <= self.config.case_ttl_s

    def root_cause(self, asset_id: str, now: float) -> str | None:
        if asset_id not in self.inventory.ids():
            return None
        for up in self.inventory.upstream_closure(asset_id):
            if self.impaired(up, now):
                return up
        return None

    def _corroboration(self, asset_id: str, now: float) -> tuple[float, list[str]]:
        best: dict[str, float] = {}
        for f in self._recent_by_asset.get(asset_id, ()):
            if now - f.created_at <= self.config.correlation_window_s:
                best[f.detector] = max(best.get(f.detector, 0.0), f.confidence)
        p_miss = 1.0
        for c in best.values():
            p_miss *= (1 - c)
        return 1 - p_miss, sorted(best)

    def _l2_capable(self, signal: str) -> bool:
        return any(fnmatch.fnmatch(signal, p) for p in self.l2_signals)

    # -- main entry ----------------------------------------------------------
    def evaluate(self, findings: list[Finding], now: float) -> list[Verdict]:
        cfg = self.config
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            f.route.append(2)
            groups[f"{f.asset_id}|{f.category.value}|{f.signal}"].append(f)

        verdicts: list[Verdict] = []
        for key, fs in groups.items():
            head = max(fs, key=lambda x: (x.severity, x.confidence))
            case = self.cases.get(key)
            if case is None:
                case = Case(key, head.asset_id, head.category, head.signal, now, now)
                self.cases[key] = case
            elif case.absent:
                case.reappearances.append(now)
                case.absent = False
            case.last_seen = now
            case.occurrences += 1
            case.findings.extend(fs)
            verdicts.append(self._judge(case, head, fs, now))

        # cases that went quiet: mark absent; expire old ones
        for key, case in list(self.cases.items()):
            if key in groups:
                continue
            case.absent = True
            if now - case.last_seen > cfg.case_ttl_s:
                del self.cases[key]
                if case.max_disposition == Disposition.MONITOR and case.occurrences <= 1:
                    for f in list(case.findings)[:1]:
                        self.memory.record(f.fingerprint, f.detector, true_positive=False)
                    verdicts.append(Verdict(key, case.asset_id, case.category, case.signal, Disposition.DISMISS,
                                            Severity.INFO, 0.0,
                                            ["transient: did not recur within case TTL; closed without action"],
                                            list(case.findings)))
        return verdicts

    def _judge(self, case: Case, head: Finding, fs: list[Finding], now: float) -> Verdict:
        cfg = self.config
        why: list[str] = []
        sev = head.severity
        corr, detectors = self._corroboration(case.asset_id, now)
        base = max(head.confidence, corr)
        if len(detectors) > 1:
            why.append(f"corroborated by {len(detectors)} detectors: {', '.join(detectors)}")
        factor = self.memory.confidence_factor(head.fingerprint, head.detector)
        conf = max(0.0, min(0.99, base * factor))
        if abs(factor - 1.0) > 0.05:
            why.append(f"historical precision factor {factor:.2f}")
        why.append(f"combined confidence {conf:.2f}; observed {case.occurrences} cycle(s)")

        def verdict(d: Disposition, root: str | None = None) -> Verdict:
            if _RANK[d] > _RANK[case.max_disposition]:
                case.max_disposition = d
            return Verdict(case.key, case.asset_id, case.category, case.signal, d, sev, round(conf, 3),
                           why, fs, root)

        if head.fingerprint in self.suppressions:
            why.append("fingerprint suppressed by operator as known-benign")
            return verdict(Disposition.DISMISS)

        mw = self.in_maintenance(case.asset_id, now)
        if mw and not (sev >= Severity.CRITICAL and case.category in (Category.SECURITY, Category.IDENTITY)):
            why.append(f"asset in maintenance window ({mw.reason or 'scheduled'})")
            return verdict(Disposition.MONITOR)

        if case.category in (Category.AVAILABILITY, Category.PERFORMANCE, Category.CAPACITY):
            root = self.root_cause(case.asset_id, now)
            if root:
                why.append(f"upstream dependency '{root}' is impaired; treated as symptom, not root cause")
                return verdict(Disposition.MONITOR, root)

        recent_flaps = [t for t in case.reappearances if now - t <= cfg.correlation_window_s * 2]
        if len(recent_flaps) >= cfg.flap_limit:
            why.append(f"flapping: reappeared {len(recent_flaps)} times; escalating for stable fix")
            return verdict(Disposition.ESCALATE)

        if conf < cfg.dismiss_below:
            why.append(f"confidence below dismissal threshold {cfg.dismiss_below}")
            return verdict(Disposition.DISMISS)

        one_shot = head.detector.startswith(("intel.", "backup."))   # assessments, not streaming signals
        if one_shot and self._l2_capable(case.signal) and sev < Severity.HIGH:
            why.append("one-shot assessment with a Level 2 review playbook")
            return verdict(Disposition.HANDLE)

        if not one_shot and sev <= Severity.LOW and case.occurrences < cfg.low_severity_persistence:
            why.append(f"low severity: waiting for {cfg.low_severity_persistence} occurrences before acting")
            return verdict(Disposition.MONITOR)

        if case.signal.startswith("anomaly:"):
            # statistical anomalies are weak evidence: they never trigger remediation by themselves
            if self.under_mitigation(case.asset_id):
                why.append("deviation expected: asset is under (or just finished) active mitigation")
                return verdict(Disposition.MONITOR)
            if case.occurrences < self.anomaly_persistence:
                why.append(f"anomaly seen {case.occurrences}x; needs {self.anomaly_persistence} to escalate")
                return verdict(Disposition.MONITOR)
            why.append("persistent unexplained anomaly; escalating for human review")
            return verdict(Disposition.ESCALATE)

        if sev >= Severity.HIGH and conf >= cfg.escalate_min:
            why.append(f"{sev.name} severity: Level 3 decision required")
            return verdict(Disposition.ESCALATE)

        if self._l2_capable(case.signal) and conf >= cfg.handle_min:
            why.append("Level 2 has an authorised low-risk playbook for this signal")
            return verdict(Disposition.HANDLE)

        if sev >= Severity.MEDIUM and conf >= cfg.escalate_min:
            why.append("no Level 2 playbook; escalating")
            return verdict(Disposition.ESCALATE)

        why.append("insufficient evidence to act; monitoring")
        return verdict(Disposition.MONITOR)
