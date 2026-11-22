import json
import unittest

from aips.intel.collectors import (HttpFetcher, load_fixture, merge_advisories, parse_feed, parse_kev, parse_nvd,
                                   parse_osv)
from aips.intel.patterns import EnvContext, extract_patterns
from aips.intel.relevance import RelevanceEngine
from aips.intel.versions import AffectedRange, Version
from aips.telemetry.inventory import Asset, Inventory, SoftwareComponent


class VersionTests(unittest.TestCase):
    def test_ordering(self):
        V = Version
        self.assertEqual(V("1.0"), V("1.0.0"))
        self.assertLess(V("1.2.3"), V("1.10.0"))
        self.assertLess(V("2.0.0-rc1"), V("2.0.0"))
        self.assertLess(V("2.0.0-beta"), V("2.0.0-rc1"))
        self.assertLess(V("1.1.1"), V("1.1.1k"))
        self.assertLess(V("1.1.1k"), V("1.1.1l"))
        self.assertLess(V("9:1.0"), V("10:0.1"))
        self.assertLess(V("v3.2.1"), V("3.2.4"))

    def test_ranges(self):
        r = AffectedRange(start_including="3.0.0", end_excluding="3.2.4")
        self.assertTrue(r.contains("3.2.1"))
        self.assertFalse(r.contains("3.2.4"))
        self.assertFalse(r.contains("2.9"))
        self.assertTrue(AffectedRange(exact="*").contains("anything"))
        self.assertTrue(AffectedRange(exact="2.1").contains("2.1.0"))
        self.assertFalse(AffectedRange().contains("1.0"))


def inventory():
    return Inventory([
        Asset("api", "service", 4, software=[SoftwareComponent("acme-gateway", "3.2.1", "acme"),
                                             SoftwareComponent("examplelib", "1.4.0", "", "PyPI")],
              attributes={"internet_facing": True}),
        Asset("db", "database", 5, software=[SoftwareComponent("postgresql", "15.3", "postgresql")]),
        Asset("cache", "service", 3, software=[SoftwareComponent("redis", "7.2.4", "redis")]),
    ])


class IntelTests(unittest.TestCase):
    def advisories(self):
        return merge_advisories(parse_nvd(json.loads(load_fixture("nvd_sample.json"))),
                                parse_kev(json.loads(load_fixture("kev_sample.json"))),
                                parse_osv(json.loads(load_fixture("osv_sample.json"))))

    def test_parsers(self):
        nvd = parse_nvd(json.loads(load_fixture("nvd_sample.json")))
        self.assertEqual(len(nvd), 3)
        self.assertEqual(nvd[0].cvss, 9.8)
        self.assertEqual(nvd[0].products[0].ranges[0].end_excluding, "3.2.4")
        osv = parse_osv(json.loads(load_fixture("osv_sample.json")))
        self.assertEqual(osv[0].products[0].ecosystem, "PyPI")
        self.assertIn("CVE-2099-10004", osv[0].aliases)

    def test_merge_marks_kev(self):
        adv = {a.id: a for a in self.advisories()}
        self.assertTrue(adv["CVE-2099-10001"].known_exploited)
        self.assertTrue(adv["CVE-2099-10001"].ransomware_use)

    def test_relevance(self):
        eng = RelevanceEngine(inventory())
        rep = eng.assess_advisories(self.advisories(), 0)
        status = {(m.advisory, m.asset_id): m.status for m in rep.matches}
        self.assertEqual(status[("CVE-2099-10001", "api")], "confirmed")
        self.assertEqual(status[("CVE-2099-10002", "db")], "not_affected")
        self.assertEqual(status[("CVE-2099-10009", "cache")], "possible")
        self.assertEqual(status[("GHSA-0000-test-0001", "api")], "confirmed")
        acme = next(f for f in rep.findings if f.tags["advisory"] == "CVE-2099-10001")
        self.assertEqual(acme.severity.name, "CRITICAL")
        self.assertEqual(acme.tags["fixed_version"], "3.2.4")
        poss = next(f for f in rep.findings if f.tags["advisory"] == "CVE-2099-10009")
        self.assertEqual(poss.severity.name, "LOW")
        self.assertEqual(len(eng.assess_advisories(self.advisories(), 0).findings), 0)   # de-duplicated

    def test_feed_and_patterns(self):
        reports = parse_feed(load_fixture("postmortems.xml"))
        self.assertEqual(len(reports), 3)
        ids = {p.id for p, _ in extract_patterns(reports[1])}
        self.assertIn("retry_storm", ids)
        self.assertIn("single_point", ids)
        rep = RelevanceEngine(inventory()).assess_reports(reports, EnvContext(inventory(), 0, None))
        self.assertTrue(any(f.tags["pattern"] == "backup_failure" for f in rep.findings))
        self.assertTrue(all(f.evidence[0].data["check_result"] for f in rep.findings))

    def test_atom_and_entity_rejection(self):
        atom = (b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>DNS outage</title>'
                b'<link href="https://e.invalid/x"/><summary>resolver failure</summary></entry></feed>')
        self.assertEqual(parse_feed(atom)[0].title, "DNS outage")
        with self.assertRaises(ValueError):
            parse_feed(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss></rss>')

    def test_fetcher_refuses_plain_http(self):
        with self.assertRaises(ValueError):
            HttpFetcher().fetch("http://example.invalid/feed")


if __name__ == "__main__":
    unittest.main()
