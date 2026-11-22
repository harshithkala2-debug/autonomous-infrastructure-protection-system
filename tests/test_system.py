"""End-to-end: every scenario's success criteria, determinism, and the HTTP API."""

import json
import logging
import unittest
import urllib.error
import urllib.request

from aips.api.server import serve
from aips.sim.scenarios import SCENARIOS, SimEnvironment, run_scenario

logging.disable(logging.CRITICAL)


class ScenarioTests(unittest.TestCase):
    def test_all_scenarios_pass(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                r, _ = run_scenario(name, seed=7)
                failed = [f"{c.name}: {c.detail}" for c in r.checks if not c.ok]
                self.assertTrue(r.passed, f"{name} failed: {failed}")

    def test_other_seeds(self):
        for name in ("service_crash", "traffic_surge", "dependency_failure", "false_alarm"):
            for seed in (1, 2, 3):
                with self.subTest(scenario=name, seed=seed):
                    self.assertTrue(run_scenario(name, seed=seed)[0].passed)

    def test_deterministic(self):
        a = run_scenario("traffic_surge", 11)[0]
        b = run_scenario("traffic_surge", 11)[0]
        self.assertEqual(a.incident_summaries, b.incident_summaries)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = SimEnvironment(seed=3)
        cls.env.sim.inject("crash", "db", 3)
        cls.env.aips.policy.kill_switch = True       # every autonomous action now needs approval
        cls.env.run(6)
        cls.token = "t" * 32
        cls.srv = serve(cls.env.aips, "127.0.0.1", 0, cls.token)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.env.cleanup()

    def call(self, method, path, body=None, token=True):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.token}"} if token else {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if r.headers.get("Content-Type", "").startswith("application/json")
                                  else raw)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read() or b"{}")

    def test_auth(self):
        self.assertEqual(self.call("GET", "/health", token=False)[0], 200)
        self.assertEqual(self.call("GET", "/status", token=False)[0], 401)
        self.assertEqual(self.call("GET", "/status")[0], 200)

    def test_incidents_approvals_flow(self):
        st, incs = self.call("GET", "/incidents")
        self.assertEqual(st, 200)
        self.assertTrue(any(i["asset"] == "db" for i in incs))
        st, pending = self.call("GET", "/approvals")
        self.assertTrue(pending, "with the kill switch engaged, remediation must wait for approval")
        ap = pending[0]
        self.assertEqual(self.call("POST", f"/approvals/{ap['id']}/approve", {})[0], 400)
        st, res = self.call("POST", f"/approvals/{ap['id']}/approve", {"approver": "oncall"})
        self.assertEqual(st, 200)
        self.assertIn(res["status"], ("approved", "pending"))
        st, inc = self.call("GET", f"/incidents/{incs[0]['id']}")
        self.assertEqual(st, 200)
        self.assertIn("timeline", inc)

    def test_metrics_audit_valves_access(self):
        st, text = self.call("GET", "/metrics")
        self.assertEqual(st, 200)
        self.assertIn("aips_incidents", text)
        self.assertTrue(self.call("GET", "/audit/verify")[1]["ok"])
        self.assertEqual(self.call("GET", "/valves")[0], 200)
        st, dec = self.call("POST", "/access-events", {"identity_id": "svc-reports", "action": "secrets.read",
                                                        "resource": "vault/x", "source_ip": "203.0.113.1"})
        self.assertFalse(dec["allowed"])
        self.assertEqual(self.call("GET", "/nope")[0], 404)
        self.assertEqual(self.call("POST", "/killswitch", {"engaged": False, "by": "test"})[0], 200)


if __name__ == "__main__":
    unittest.main()
