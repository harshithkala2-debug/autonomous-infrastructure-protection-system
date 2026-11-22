"""Escalation routing (concept section 2, "Escalation paths").

Ordinary findings go Level 1 -> Level 2. Findings whose severity/confidence
already establish a serious incident bypass Level 2 and go straight to
Level 3, so containment is not delayed by an intermediate review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.models import Category, Finding, Level, Severity


@dataclass
class EscalationConfig:
    direct_severity: Severity = Severity.CRITICAL
    high_confidence_bypass: float = 0.9
    sensitive_categories: set[Category] = field(
        default_factory=lambda: {Category.SECURITY, Category.IDENTITY, Category.DATA_INTEGRITY})
    sensitive_min_severity: Severity = Severity.HIGH
    sensitive_min_confidence: float = 0.75

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EscalationConfig":
        c = cls()
        if "direct_severity" in d:
            c.direct_severity = Severity.parse(d["direct_severity"])
        if "high_confidence_bypass" in d:
            c.high_confidence_bypass = float(d["high_confidence_bypass"])
        if "sensitive_categories" in d:
            c.sensitive_categories = {Category(x) for x in d["sensitive_categories"]}
        if "sensitive_min_severity" in d:
            c.sensitive_min_severity = Severity.parse(d["sensitive_min_severity"])
        if "sensitive_min_confidence" in d:
            c.sensitive_min_confidence = float(d["sensitive_min_confidence"])
        return c


class EscalationRouter:
    def __init__(self, config: EscalationConfig | None = None):
        self.config = config or EscalationConfig()

    def route(self, f: Finding) -> tuple[Level, str]:
        c = self.config
        if f.severity >= c.direct_severity and f.confidence >= 0.5:
            return Level.L3_DECISION, f"severity {f.severity.name} warrants immediate Level 3 decision"
        if f.severity >= Severity.HIGH and f.confidence >= c.high_confidence_bypass:
            return Level.L3_DECISION, f"HIGH severity with confidence {f.confidence:.2f} bypasses Level 2"
        if (f.category in c.sensitive_categories and f.severity >= c.sensitive_min_severity
                and f.confidence >= c.sensitive_min_confidence):
            return Level.L3_DECISION, f"{f.category.value} finding at {f.severity.name} bypasses Level 2"
        return Level.L2_EVALUATION, "standard path: Level 2 evaluation"
