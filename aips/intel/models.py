"""Normalised intelligence records produced by every collector."""

from __future__ import annotations

from dataclasses import dataclass, field

from .versions import AffectedRange


@dataclass
class AffectedProduct:
    product: str
    vendor: str = ""
    ecosystem: str = ""
    ranges: list[AffectedRange] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)     # explicit affected versions (OSV)

    @property
    def fixed_versions(self) -> list[str]:
        return [r.fixed for r in self.ranges if r.fixed]


@dataclass
class Advisory:
    id: str
    source: str
    title: str
    summary: str = ""
    published: str = ""
    cvss: float | None = None
    cwes: list[str] = field(default_factory=list)
    products: list[AffectedProduct] = field(default_factory=list)
    known_exploited: bool = False
    ransomware_use: bool = False
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    required_action: str = ""

    @property
    def all_ids(self) -> set[str]:
        return {self.id, *self.aliases}


@dataclass
class IncidentReport:
    id: str
    source: str
    title: str
    url: str = ""
    published: str = ""
    text: str = ""


@dataclass
class SourceReliability:
    """Weighting of a source's claims (official databases > vendor blogs > aggregators)."""

    name: str
    weight: float


DEFAULT_RELIABILITY = {
    "nvd": 0.95, "cisa-kev": 0.98, "osv": 0.9, "vendor-advisory": 0.9, "postmortem": 0.75, "blog": 0.6,
    "fixture": 0.9,
}
