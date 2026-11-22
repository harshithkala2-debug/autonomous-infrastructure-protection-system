"""Google Cloud integration, tested against the in-process API emulator."""

import logging
import tomllib
import unittest

from aips.core.audit import AuditLedger
from aips.core.clock import ManualClock
from aips.core.models import ActionRequest, IncidentStatus
from aips.identity.guard import GuardConfig, Identity, IdentityGuard, PermissionBoundary, PermissionRule
from aips.integrations.gcp import GcpAdapter, GcpClient, GcpDiscovery, GcpError, GcpTelemetrySource
from aips.integrations.gcp.auth import AuthError, ChainToken, GcloudToken, StaticToken
from aips.integrations.gcp.discovery import GcpInstance, exposed_ports
from aips.integrations.gcp.emulator import FakeGcp
from aips.integrations.gcp.sources import normalize_action
from aips.orchestrator import AIPS, AIPSConfig
from aips.telemetry.inventory import Inventory

logging.disable(logging.CRITICAL)
T0 = 1_800_000_000.0


def project():
    g = FakeGcp()
    g.add_mig("web", 2, tags=["web"])
    g.add_instance("bastion", tags=["ssh"])
    g.add_firewall("allow-http", ["80", "443"], tags=["web"])
    g.add_firewall("allow-ssh", ["22"], source="35.235.240.0/20", tags=["ssh"])
    g.add_service_account("app-sa@demo-project.iam.gserviceaccount.com")
    g.uptime["web-check"] = 1.0
    return g


def client(g):
    return GcpClient(g.project, StaticToken("t"), transport=g, sleep=lambda s: None)


class AuthAndClientTests(unittest.TestCase):
    def test_token_chain(self):
        ch = ChainToken([GcloudToken(runner=lambda *a, **k: None), StaticToken("abc")])
        self.assertEqual(ch.token(), "abc")
        self.assertEqual(ch.used, "env")
        with self.assertRaises(AuthError):
            ChainToken([]).token()

    def test_retry_pagination_errors_and_https(self):
        calls = {"n": 0}

        def flaky(method, url, headers, body):
            calls["n"] += 1
            self.assertEqual(headers["Authorization"], "Bearer t")
            if calls["n"] == 1:
                return 503, {}
            if "pageToken" not in url:
                return 200, {"items": [1, 2], "nextPageToken": "p2"}
            return 200, {"items": [3]}
        c = GcpClient("p", StaticToken("t"), transport=flaky, sleep=lambda s: None)
        self.assertEqual(list(c.pages("https://x.googleapis.com/list", "items")), [1, 2, 3])
        c2 = GcpClient("p", None, transport=lambda *a: (403, {"error": {"message": "denied"}}), sleep=lambda s: None)
        with self.assertRaises(GcpError) as ctx:
            c2.get("https://x.googleapis.com/y")
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(ValueError):
            c2.get("http://x.googleapis.com/y")

    def test_operation_wait(self):
        g = project()
        c = client(g)
        op = c.post(f"{c.compute}/zones/{g.zone}/instances/bastion/reset")
        self.assertEqual(op["status"], "RUNNING")
        self.assertEqual(c.wait(op)["status"], "DONE")


class DiscoveryTests(unittest.TestCase):
    def test_topology_and_inventory(self):
        g = project()
        topo = GcpDiscovery(client(g)).topology()
        self.assertEqual(set(topo.migs), {"web"})
        self.assertEqual(topo.migs["web"].instances, ["web-0000", "web-0001"])
        self.assertEqual(topo.instances["web-0000"].mig, "web")
        inv = GcpDiscovery.inventory(topo)
        self.assertEqual(inv.get("web-0000").allowed_ports, [80, 443])
        self.assertEqual(inv.get("bastion").allowed_ports, [])          # ssh only from Google IAP range
        self.assertEqual(inv.get("web").attributes["replicas"], 2)
        self.assertIsNotNone(inv.get("net-default"))
        parsed = Inventory.from_dict(tomllib.loads(GcpDiscovery.to_toml(inv)))
        self.assertEqual(len(parsed), len(inv))

    def test_exposure_follows_gcp_priority_rules(self):
        inst = GcpInstance("vm", "z", "1", "RUNNING", ["web"], "", "default", "1.2.3.4")
        fw = [{"name": "allow", "network": "x/default", "sourceRanges": ["0.0.0.0/0"],
               "allowed": [{"IPProtocol": "tcp", "ports": ["80", "4444"]}], "priority": 1000},
              {"name": "deny", "network": "x/default", "sourceRanges": ["0.0.0.0/0"],
               "denied": [{"IPProtocol": "tcp", "ports": ["4444"]}], "priority": 100}]
        self.assertEqual(exposed_ports(inst, fw), [80])
        fw[1]["priority"] = 2000                                         # lower precedence: allow wins
        self.assertEqual(exposed_ports(inst, fw), [80, 4444])
        fw[1]["priority"] = 1000                                         # tie: deny wins
        self.assertEqual(exposed_ports(inst, fw), [80])


class SourceTests(unittest.TestCase):
    def test_normalize_action(self):
        self.assertEqual(normalize_action("iam.googleapis.com", "google.iam.admin.v1.CreateServiceAccountKey"),
                         "iam.createserviceaccountkey")
        self.assertEqual(normalize_action("storage.googleapis.com", "storage.objects.get"), "storage.objects.get")
        self.assertEqual(normalize_action("compute.googleapis.com", "v1.compute.instances.delete"),
                         "compute.instances.delete")
        self.assertTrue(normalize_action("secretmanager.googleapis.com",
                                         "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion")
                        .startswith("secrets."))

    def test_collect_maps_everything(self):
        g = project()
        g.cpu["web-0000"], g.cpu["web-0001"] = 0.5, 0.7
        g.audit("app-sa@demo-project.iam.gserviceaccount.com", "storage.googleapis.com", "storage.objects.get",
                "projects/_/buckets/b/objects/o", "10.0.0.5", T0)
        g.findings.append({"name": "f1", "category": "OPEN_FIREWALL", "severity": "HIGH",
                           "resourceName": f"//compute.googleapis.com/projects/p/zones/z/instances/{g.instances['bastion']['id']}"})
        src = GcpTelemetrySource(client(g), uptime_checks={"web-check": "web"})
        obs = src.collect(T0)
        self.assertEqual(obs.metric("web-0000", "cpu_pct"), 50.0)
        self.assertAlmostEqual(obs.metric("web", "cpu_pct"), 60.0)
        self.assertTrue(obs.service_up["web"])
        self.assertEqual(obs.open_ports["web-0001"], [80, 443])
        self.assertIn("allow-http", obs.configs["net-default"])
        acc = [e for e in obs.events if e["type"] == "access"]
        self.assertEqual(acc[0]["action"], "storage.objects.get")
        alerts = [e for e in obs.events if e["type"] == "alert"]
        self.assertEqual(alerts[0]["asset"], "bastion")
        self.assertEqual(alerts[0]["signal"], "scc:open_firewall")
        self.assertFalse([e for e in src.collect(T0 + 30).events if e["type"] == "alert"])   # de-duplicated

    def test_one_failing_api_does_not_blind_the_rest(self):
        g = project()
        g.fail["logging.googleapis.com"] = 403
        src = GcpTelemetrySource(client(g), uptime_checks={"web-check": "web"})
        obs = src.collect(T0)
        self.assertIn("audit_logs", src.errors)
        self.assertIsNotNone(obs.metric("web-0000", "cpu_pct"))

    def test_aips_rules_and_disabled_rules_are_not_drift_state(self):
        g = project()
        g.add_firewall("aips-block-4444-x", ["4444"], deny=True, priority=100)
        g.add_firewall("old", ["8080"])
        g.firewalls["old"]["disabled"] = True
        obs = GcpTelemetrySource(client(g)).collect(T0)
        self.assertEqual(set(obs.configs["net-default"]), {"allow-http", "allow-ssh"})


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.g = project()
        self.a = GcpAdapter(client(self.g))

    def test_restart_scale_and_rollback(self):
        self.g.instances["web-0001"]["status"] = "TERMINATED"
        self.assertTrue(self.a.execute(ActionRequest("service.restart", "web")).success)
        self.assertEqual(self.g.instances["web-0001"]["status"], "RUNNING")
        r = self.a.execute(ActionRequest("service.scale_out", "web", {"replicas": 2}))
        self.assertTrue(r.success, r.detail)
        self.assertEqual(self.g.migs["web"]["targetSize"], 4)
        self.assertTrue(self.a.rollback(r).success)
        self.assertEqual(self.g.migs["web"]["targetSize"], 2)

    def test_block_port_isolate_and_rollback(self):
        r = self.a.execute(ActionRequest("network.block_port", "bastion", {"port": 4444}))
        self.assertTrue(r.success, r.detail)
        rule = self.g.firewalls[r.rollback["firewall"]]
        self.assertEqual(rule["priority"], 100)
        self.assertEqual(rule["denied"][0]["ports"], ["4444"])
        self.assertTrue(self.a.rollback(r).success)
        self.assertNotIn(r.rollback["firewall"], self.g.firewalls)
        iso = self.a.execute(ActionRequest("host.isolate", "bastion"))
        self.assertTrue(iso.success, iso.detail)
        self.assertIn("aips-quarantine", self.g.instances["bastion"]["tags"]["items"])
        self.assertTrue(any(n.startswith("aips-quarantine-ingress") for n in self.g.firewalls))
        self.assertTrue(self.a.rollback(iso).success)
        self.assertNotIn("aips-quarantine", self.g.instances["bastion"]["tags"]["items"])

    def test_identity_freeze_and_refusals(self):
        sa = "app-sa@demo-project.iam.gserviceaccount.com"
        self.assertTrue(self.a.freeze_identity(sa, True)[0])
        self.assertTrue(self.g.service_accounts[sa]["disabled"])
        self.a.freeze_identity(sa, False)
        self.assertFalse(self.g.service_accounts[sa]["disabled"])
        self.assertFalse(self.a.freeze_identity("alice@example.com", True)[0])
        self.assertFalse(self.a.execute(ActionRequest("service.restart", "Bad_Name;rm")).success)
        self.assertFalse(self.a.execute(ActionRequest("storage.expand", "web")).success)


class EndToEndTests(unittest.TestCase):
    """AIPS running against the emulated project: detect, decide, act through the real adapter, verify."""

    def build(self, g):
        clock = ManualClock(T0)
        c = client(g)
        topo = GcpDiscovery(c).topology()
        inv = GcpDiscovery.inventory(topo)
        guard = IdentityGuard(GuardConfig(auto_register_unknown=True))
        guard.register(Identity("app-sa@demo-project.iam.gserviceaccount.com", "service"),
                       PermissionBoundary(allow=[PermissionRule("storage.objects.get", "projects/_/buckets/app/*")],
                                          source_networks=["10.0.0.0/8"]))
        src = GcpTelemetrySource(c, uptime_checks={"web-check": "web"}, clock=clock.now)
        adapter = GcpAdapter(c, topo)
        aips = AIPS(inv, adapter, [src], clock=clock, config=AIPSConfig(), guard=guard,
                    audit=AuditLedger(clock=clock, key=b"k"))
        adapter.baselines = aips.baselines
        obs = src.collect(clock.now())
        aips.last_obs = obs
        for asset in obs.configs:
            aips.capture_baseline(asset, "test")
        return aips, clock

    def run_ticks(self, aips, clock, n):
        for _ in range(n):
            aips.tick()
            clock.advance(30)

    def test_rogue_firewall_rule_is_contained_and_reverted(self):
        g = project()
        aips, clock = self.build(g)
        self.run_ticks(aips, clock, 2)
        g.add_firewall("debug-open", ["4444"], tags=["web"])                   # someone opens a port to the world
        self.run_ticks(aips, clock, 8)
        kinds = [a.kind for i in aips.engine.incidents.values() for a in i.actions]
        self.assertIn("network.block_port", kinds)
        self.assertIn("config.restore_baseline", kinds)
        self.assertTrue(g.firewalls["debug-open"]["disabled"], "unapproved rule disabled, not deleted")
        self.assertFalse(any(4444 in p for p in [exposed_ports(i, list(g.firewalls.values()))
                                                  for i in GcpDiscovery(client(g)).topology().instances.values()]))
        self.assertTrue(all(i.status == IncidentStatus.RESOLVED for i in aips.engine.incidents.values()),
                        [(i.signal, i.status.value) for i in aips.engine.incidents.values()])

    def test_crashed_mig_is_restarted(self):
        g = project()
        aips, clock = self.build(g)
        self.run_ticks(aips, clock, 2)
        g.instances["web-0001"]["status"] = "TERMINATED"
        self.run_ticks(aips, clock, 6)
        self.assertEqual(g.instances["web-0001"]["status"], "RUNNING")
        incs = [i for i in aips.engine.incidents.values() if i.asset_id == "web"]
        self.assertTrue(incs and incs[0].status == IncidentStatus.RESOLVED, [(i.signal, i.status) for i in incs])

    def test_service_account_misuse_is_frozen_in_iam(self):
        g = project()
        aips, clock = self.build(g)
        self.run_ticks(aips, clock, 1)
        sa = "app-sa@demo-project.iam.gserviceaccount.com"
        g.audit(sa, "iam.googleapis.com", "google.iam.admin.v1.CreateServiceAccountKey",
                f"projects/-/serviceAccounts/{sa}", "203.0.113.9", clock.now())
        g.audit(sa, "secretmanager.googleapis.com",
                "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                "projects/p/secrets/db-password/versions/latest", "203.0.113.9", clock.now())
        self.run_ticks(aips, clock, 3)
        self.assertTrue(aips.guard.is_frozen(sa))
        self.assertTrue(g.service_accounts[sa]["disabled"], "freeze enforced in Google Cloud IAM")
        self.assertTrue(aips.audit.verify()[0])


if __name__ == "__main__":
    unittest.main()
