"""Outcome memory: findings and outcomes inform future evaluation (concept section 8, step 9).

Each resolved incident counts as a true positive for the fingerprints and
detectors that raised it; each dismissed case, rejected action, or granted
identity appeal counts as a false positive. Level 2 multiplies its confidence
by a factor derived from a Beta(1,1)-smoothed precision estimate, so noisy
detectors lose influence and reliable ones gain it - without ever being
silenced entirely.
"""

from __future__ import annotations

import json
import threading
from collections import defaultdict
from pathlib import Path


class OutcomeMemory:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._fp: dict[str, list[int]] = defaultdict(lambda: [0, 0])     # fingerprint -> [tp, fp]
        self._det: dict[str, list[int]] = defaultdict(lambda: [0, 0])    # detector -> [tp, fp]
        self._lock = threading.Lock()
        if self.path and self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._fp.update({k: list(v) for k, v in data.get("fingerprints", {}).items()})
            self._det.update({k: list(v) for k, v in data.get("detectors", {}).items()})

    def record(self, fingerprint: str, detector: str, true_positive: bool) -> None:
        idx = 0 if true_positive else 1
        with self._lock:
            self._fp[fingerprint][idx] += 1
            self._det[detector][idx] += 1
        self.save()

    @staticmethod
    def _precision(tp: int, fp: int) -> float:
        return (tp + 1) / (tp + fp + 2)

    def precision(self, fingerprint: str, detector: str) -> float:
        with self._lock:
            ftp, ffp = self._fp.get(fingerprint, (0, 0))
            dtp, dfp = self._det.get(detector, (0, 0))
        # fingerprint-specific evidence dominates once it exists
        w = min(1.0, (ftp + ffp) / 5)
        return w * self._precision(ftp, ffp) + (1 - w) * self._precision(dtp, dfp)

    def confidence_factor(self, fingerprint: str, detector: str) -> float:
        """1.0 with no history; range [0.6, 1.4]."""
        return 0.6 + 0.8 * self.precision(fingerprint, detector)

    def snapshot(self) -> dict:
        with self._lock:
            return {"fingerprints": dict(self._fp), "detectors": dict(self._det)}

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.snapshot(), indent=2), encoding="utf-8")
