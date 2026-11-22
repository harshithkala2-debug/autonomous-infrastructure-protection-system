"""Collectors for public intelligence sources.

* ``NVDCollector``   - NIST National Vulnerability Database CVE API 2.0
* ``KEVCollector``   - CISA Known Exploited Vulnerabilities catalogue
* ``OSVCollector``   - OSV.dev per-package queries for the exact versions in the inventory
* ``FeedCollector``  - RSS/Atom feeds of engineering blogs, status pages and postmortems

All network access goes through ``HttpFetcher``: HTTPS only by default,
bounded response size, timeouts, per-host rate limiting and an on-disk cache.
Every parser also accepts raw JSON/XML so the same code runs offline against
the bundled fixtures (``aips/data``).
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

from .. import __version__
from ..telemetry.inventory import Inventory
from .models import Advisory, AffectedProduct, IncidentReport
from .versions import AffectedRange

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/query"
USER_AGENT = f"aips-intel/{__version__}"
MAX_BYTES = 25 * 1024 * 1024


class HttpFetcher:
    def __init__(self, cache_dir: str | Path | None = None, min_interval_s: float = 6.0, timeout: float = 30.0,
                 cache_ttl_s: float = 3600, allow_http: bool = False, headers: dict[str, str] | None = None):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.min_interval = min_interval_s
        self.timeout = timeout
        self.ttl = cache_ttl_s
        self.allow_http = allow_http
        self.headers = headers or {}
        self._last: dict[str, float] = {}

    def _cache_path(self, key: str) -> Path | None:
        if not self.cache_dir:
            return None
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir / (hashlib.sha256(key.encode()).hexdigest() + ".cache")

    def fetch(self, url: str, data: bytes | None = None, content_type: str = "application/json") -> bytes:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" and not (self.allow_http and parsed.scheme == "http"):
            raise ValueError(f"refusing non-HTTPS URL {url}")
        key = url + (hashlib.sha256(data).hexdigest() if data else "")
        cp = self._cache_path(key)
        if cp and cp.exists() and time.time() - cp.stat().st_mtime < self.ttl:
            return cp.read_bytes()
        host = parsed.netloc
        wait = self.min_interval - (time.time() - self._last.get(host, 0))
        if wait > 0:
            time.sleep(wait)
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json, application/xml, text/xml, */*",
                   **self.headers}
        if data is not None:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - scheme checked above
            body = resp.read(MAX_BYTES + 1)
        self._last[host] = time.time()
        if len(body) > MAX_BYTES:
            raise ValueError(f"response from {host} exceeds {MAX_BYTES} bytes")
        if cp:
            cp.write_bytes(body)
        return body


# --------------------------------------------------------------------------- NVD
def _parse_cpe(criteria: str) -> tuple[str, str, str]:
    # cpe:2.3:part:vendor:product:version:update:...
    parts = criteria.split(":")
    if len(parts) < 6:
        return "", "", "*"
    return parts[3].replace("\\", ""), parts[4].replace("\\", ""), parts[5]


def parse_nvd(doc: dict[str, Any]) -> list[Advisory]:
    out = []
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        score = None
        metrics = cve.get("metrics", {})
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                score = float(metrics[k][0].get("cvssData", {}).get("baseScore", 0)) or None
                break
        cwes = [d.get("value") for w in cve.get("weaknesses", []) for d in w.get("description", [])
                if d.get("value", "").startswith("CWE-")]
        products: dict[tuple[str, str], AffectedProduct] = {}
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable", True):
                        continue
                    vendor, product, ver = _parse_cpe(m.get("criteria", ""))
                    if not product:
                        continue
                    ap = products.setdefault((vendor, product), AffectedProduct(product=product, vendor=vendor))
                    rng = AffectedRange(m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                                        m.get("versionEndIncluding"), m.get("versionEndExcluding"),
                                        None if ver in ("*", "-", "") else ver)
                    if not any([rng.start_including, rng.start_excluding, rng.end_including, rng.end_excluding,
                                rng.exact]):
                        rng.exact = "*"     # all versions
                    ap.ranges.append(rng)
        out.append(Advisory(
            id=cid, source="nvd", title=desc[:120] or cid, summary=desc, published=cve.get("published", ""),
            cvss=score, cwes=cwes, products=list(products.values()),
            references=[r.get("url") for r in cve.get("references", []) if r.get("url")][:10]))
    return out


class NVDCollector:
    source = "nvd"

    def __init__(self, fetcher: HttpFetcher, api_key: str | None = None):
        self.fetcher = fetcher
        if api_key:
            self.fetcher.headers["apiKey"] = api_key

    def recent(self, days: int = 7, page_size: int = 2000) -> list[Advisory]:
        end = time.gmtime()
        start = time.gmtime(time.time() - days * 86400)
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        params = {"lastModStartDate": time.strftime(fmt, start), "lastModEndDate": time.strftime(fmt, end),
                  "resultsPerPage": str(page_size), "startIndex": "0"}
        out: list[Advisory] = []
        while True:
            doc = json.loads(self.fetcher.fetch(f"{NVD_URL}?{urllib.parse.urlencode(params)}"))
            out.extend(parse_nvd(doc))
            total = int(doc.get("totalResults", 0))
            nxt = int(params["startIndex"]) + int(doc.get("resultsPerPage", page_size))
            if nxt >= total or not doc.get("vulnerabilities"):
                return out
            params["startIndex"] = str(nxt)

    def by_cve(self, cve_id: str) -> list[Advisory]:
        return parse_nvd(json.loads(self.fetcher.fetch(f"{NVD_URL}?cveId={urllib.parse.quote(cve_id)}")))


# --------------------------------------------------------------------------- KEV
def parse_kev(doc: dict[str, Any]) -> list[Advisory]:
    out = []
    for v in doc.get("vulnerabilities", []):
        out.append(Advisory(
            id=v["cveID"], source="cisa-kev", title=v.get("vulnerabilityName", v["cveID"]),
            summary=v.get("shortDescription", ""), published=v.get("dateAdded", ""),
            products=[AffectedProduct(product=v.get("product", ""), vendor=v.get("vendorProject", ""))],
            known_exploited=True, ransomware_use=str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            required_action=v.get("requiredAction", ""), cwes=list(v.get("cwes", []))))
    return out


class KEVCollector:
    source = "cisa-kev"

    def __init__(self, fetcher: HttpFetcher):
        self.fetcher = fetcher

    def fetch(self) -> list[Advisory]:
        return parse_kev(json.loads(self.fetcher.fetch(KEV_URL)))


# --------------------------------------------------------------------------- OSV
def parse_osv(doc: dict[str, Any]) -> list[Advisory]:
    vulns = doc.get("vulns", [doc] if "id" in doc and "affected" in doc else [])
    out = []
    for v in vulns:
        products = []
        for aff in v.get("affected", []):
            pkg = aff.get("package", {})
            ap = AffectedProduct(product=pkg.get("name", ""), ecosystem=pkg.get("ecosystem", ""),
                                 versions=list(aff.get("versions", [])))
            for r in aff.get("ranges", []):
                if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                    continue
                intro = None
                for ev in r.get("events", []):
                    if "introduced" in ev:
                        intro = ev["introduced"]
                    elif "fixed" in ev:
                        ap.ranges.append(AffectedRange(start_including=None if intro in (None, "0") else intro,
                                                       end_excluding=ev["fixed"]))
                        intro = None
                    elif "last_affected" in ev:
                        ap.ranges.append(AffectedRange(start_including=None if intro in (None, "0") else intro,
                                                       end_including=ev["last_affected"]))
                        intro = None
                if intro is not None:
                    ap.ranges.append(AffectedRange(start_including="0" if intro == "0" else intro))
            products.append(ap)
        score = None
        for s in v.get("severity", []):
            try:
                score = float(s.get("score"))
            except (TypeError, ValueError):
                pass
        dbs = v.get("database_specific", {}) or {}
        if score is None and isinstance(dbs.get("cvss_score"), (int, float)):
            score = float(dbs["cvss_score"])
        out.append(Advisory(
            id=v["id"], source="osv", title=v.get("summary", v["id"]), summary=v.get("details", ""),
            published=v.get("published", ""), cvss=score, products=products, aliases=list(v.get("aliases", [])),
            references=[r.get("url") for r in v.get("references", []) if r.get("url")][:10],
            cwes=list(dbs.get("cwe_ids", []))))
    return out


class OSVCollector:
    source = "osv"

    def __init__(self, fetcher: HttpFetcher):
        self.fetcher = fetcher

    def query_inventory(self, inventory: Inventory) -> list[Advisory]:
        out: list[Advisory] = []
        seen: set[tuple[str, str, str]] = set()
        for asset in inventory:
            for sw in asset.software:
                if not sw.ecosystem or (sw.name, sw.ecosystem, sw.version) in seen:
                    continue
                seen.add((sw.name, sw.ecosystem, sw.version))
                body = json.dumps({"package": {"name": sw.name, "ecosystem": sw.ecosystem},
                                   "version": sw.version}).encode()
                out.extend(parse_osv(json.loads(self.fetcher.fetch(OSV_URL, data=body))))
        return out


# --------------------------------------------------------------------------- RSS / Atom
_ATOM = "{http://www.w3.org/2005/Atom}"


def _strip_html(s: str) -> str:
    import html
    import re
    return html.unescape(re.sub(r"<[^>]+>", " ", s or "")).strip()


def parse_feed(xml_bytes: bytes, source: str = "postmortem") -> list[IncidentReport]:
    if len(xml_bytes) > MAX_BYTES:
        raise ValueError("feed too large")
    if b"<!ENTITY" in xml_bytes[:4096].upper():
        raise ValueError("feeds declaring XML entities are rejected")
    root = ET.fromstring(xml_bytes)
    out = []
    for item in root.iter("item"):
        title = item.findtext("title", "")
        link = item.findtext("link", "")
        out.append(IncidentReport(id=hashlib.sha256((link or title).encode()).hexdigest()[:12], source=source,
                                  title=title, url=link, published=item.findtext("pubDate", ""),
                                  text=_strip_html(item.findtext("description", ""))))
    for entry in root.iter(f"{_ATOM}entry"):
        title = entry.findtext(f"{_ATOM}title", "")
        link_el = entry.find(f"{_ATOM}link")
        link = link_el.get("href", "") if link_el is not None else ""
        text = entry.findtext(f"{_ATOM}content", "") or entry.findtext(f"{_ATOM}summary", "")
        out.append(IncidentReport(id=hashlib.sha256((link or title).encode()).hexdigest()[:12], source=source,
                                  title=title, url=link, published=entry.findtext(f"{_ATOM}updated", ""),
                                  text=_strip_html(text)))
    return out


class FeedCollector:
    source = "feed"

    def __init__(self, fetcher: HttpFetcher, urls: Iterable[str], source: str = "postmortem"):
        self.fetcher, self.urls, self.kind = fetcher, list(urls), source

    def fetch(self) -> list[IncidentReport]:
        out = []
        for u in self.urls:
            out.extend(parse_feed(self.fetcher.fetch(u), self.kind))
        return out


def merge_advisories(*groups: Iterable[Advisory]) -> list[Advisory]:
    """De-duplicate across sources by CVE/alias, combining product data and KEV flags."""
    by_id: dict[str, Advisory] = {}
    for group in groups:
        for adv in group:
            existing = next((by_id[i] for i in adv.all_ids if i in by_id), None)
            if existing is None:
                for i in adv.all_ids:
                    by_id[i] = adv
                continue
            existing.known_exploited |= adv.known_exploited
            existing.ransomware_use |= adv.ransomware_use
            existing.cvss = existing.cvss if existing.cvss is not None else adv.cvss
            existing.required_action = existing.required_action or adv.required_action
            have = {(p.vendor.lower(), p.product.lower()) for p in existing.products if p.ranges or p.versions}
            for p in adv.products:
                if (p.ranges or p.versions) and (p.vendor.lower(), p.product.lower()) not in have:
                    existing.products.append(p)
            if not any(p.ranges or p.versions for p in existing.products):
                existing.products.extend(p for p in adv.products if p not in existing.products)
            existing.aliases = sorted(set(existing.aliases) | adv.all_ids - {existing.id})
            for i in adv.all_ids:
                by_id[i] = existing
    uniq: dict[int, Advisory] = {id(a): a for a in by_id.values()}
    return list(uniq.values())


def load_fixture(name: str) -> bytes:
    return (Path(__file__).resolve().parent.parent / "data" / name).read_bytes()
