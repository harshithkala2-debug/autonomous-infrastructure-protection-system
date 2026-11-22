"""Relevance engine: decides whether public intelligence applies to *this* environment.

Advisories
    Product names are normalised (aliases, vendor) and matched against every
    software component in the inventory, then the installed version is tested
    against the advisory's affected ranges:

    * version inside a range          -> **confirmed exposure** (finding)
    * product matches, no range data  -> **possible exposure**, LOW severity,
                                         asks a human to confirm the version
    * version outside every range     -> not affected (recorded, no finding)

    Severity comes from CVSS, raised one step if the vulnerability is known to be
    exploited (CISA KEV) and one step if the asset is internet-facing.

Incident reports
    Failure patterns are extracted, then each pattern's environment check runs.
    Findings cite the source report but are based only on the check's result.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.models import Category, Evidence, Finding, Severity
from ..telemetry.inventory import Inventory, normalize_product
from .models import DEFAULT_RELIABILITY, Advisory, IncidentReport
from .patterns import EnvContext, extract_patterns


def cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass
class MatchRecord:
    advisory: str
    asset_id: str
    package: str
    installed: str
    status: str             # confirmed | possible | not_affected
    fixed_version: str | None = None


@dataclass
class RelevanceReport:
    findings: list[Finding] = field(default_factory=list)
    matches: list[MatchRecord] = field(default_factory=list)
    reports_checked: int = 0
    advisories_checked: int = 0


class RelevanceEngine:
    name = "intel.relevance"

    def __init__(self, inventory: Inventory, reliability: dict[str, float] | None = None):
        self.inventory = inventory
        self.reliability = reliability or DEFAULT_RELIABILITY
        self._seen: set[tuple[str, str, str]] = set()

    def _vendor_ok(self, adv_vendor: str, sw_vendor: str) -> bool:
        if not adv_vendor or not sw_vendor:
            return True
        a, b = normalize_product(adv_vendor), normalize_product(sw_vendor)
        return a == b or a in b or b in a

    def assess_advisories(self, advisories: list[Advisory], now: float) -> RelevanceReport:
        rep = RelevanceReport(advisories_checked=len(advisories))
        for adv in advisories:
            weight = self.reliability.get(adv.source, 0.7)
            for prod in adv.products:
                for asset, sw in self.inventory.find_software(prod.product):
                    if not self._vendor_ok(prod.vendor, sw.vendor):
                        continue
                    if prod.ecosystem and sw.ecosystem and prod.ecosystem.lower() != sw.ecosystem.lower():
                        continue
                    has_data = bool(prod.ranges or prod.versions)
                    in_range = (sw.version in prod.versions) or any(r.contains(sw.version) for r in prod.ranges)
                    fixed = next((f for f in prod.fixed_versions), None)
                    if has_data and not in_range:
                        rep.matches.append(MatchRecord(adv.id, asset.id, sw.name, sw.version, "not_affected", fixed))
                        continue
                    status = "confirmed" if in_range else "possible"
                    rep.matches.append(MatchRecord(adv.id, asset.id, sw.name, sw.version, status, fixed))
                    key = (adv.id, asset.id, sw.name)
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    if status == "confirmed":
                        sev = cvss_to_severity(adv.cvss)
                        if adv.known_exploited:
                            sev = sev.bump(1)
                        if asset.attributes.get("internet_facing"):
                            sev = sev.bump(1)
                        conf = 0.95 * weight
                    else:
                        sev, conf = Severity.LOW, 0.5 * weight
                    reasons = [f"{sw.name} {sw.version} on {asset.id}"
                               + (" is within the affected range" if in_range else
                                  " matches the product; version range not published - confirm manually")]
                    if adv.known_exploited:
                        reasons.append("listed in CISA Known Exploited Vulnerabilities")
                    if adv.ransomware_use:
                        reasons.append("known ransomware campaign use")
                    rep.findings.append(Finding(
                        detector=self.name, category=Category.VULNERABILITY, severity=sev,
                        confidence=round(conf, 3), asset_id=asset.id,
                        title=f"{adv.id}: {sw.name} {sw.version} on {asset.id} ({status})",
                        description="; ".join(reasons) + (f". Required action: {adv.required_action}"
                                                          if adv.required_action else ""),
                        created_at=now, signal="vulnerable_component" if status == "confirmed" else "possible_exposure",
                        tags={"advisory": adv.id, "package": sw.name, "installed": sw.version,
                              "fixed_version": fixed or "latest", "key": adv.id},
                        evidence=[Evidence("advisory", adv.source, {
                            "id": adv.id, "cvss": adv.cvss, "kev": adv.known_exploited, "cwes": adv.cwes,
                            "references": adv.references[:3], "status": status}, now)]))
        return rep

    def assess_reports(self, reports: list[IncidentReport], ctx: EnvContext) -> RelevanceReport:
        rep = RelevanceReport(reports_checked=len(reports))
        for r in reports:
            weight = self.reliability.get(r.source, 0.7)
            for pattern, score in extract_patterns(r):
                for asset_id, detail in pattern.check(ctx):
                    key = (pattern.id, asset_id, detail)
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    crit = self.inventory.criticality(asset_id)
                    sev = Severity.MEDIUM if crit >= 4 else Severity.LOW
                    rep.findings.append(Finding(
                        detector=self.name, category=Category.VULNERABILITY, severity=sev,
                        confidence=round(min(0.9, (0.55 + 0.1 * score) * weight + 0.1), 3), asset_id=asset_id,
                        title=f"Exposure to '{pattern.name}' (seen in: {r.title[:60]})",
                        description=f"{detail}. Recommendation: {pattern.recommendation}",
                        created_at=ctx.now, signal=f"intel_pattern:{pattern.id}",
                        tags={"pattern": pattern.id, "report": r.id, "key": f"{pattern.id}:{detail[:40]}"},
                        evidence=[Evidence("incident_report", r.source, {
                            "report": r.title, "url": r.url, "pattern_score": score, "check_result": detail}, ctx.now)]))
        return rep
