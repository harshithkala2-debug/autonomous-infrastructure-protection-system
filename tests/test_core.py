import json
import tempfile
import unittest
from pathlib import Path

from aips.core.audit import AuditLedger
from aips.core.bus import EventBus
from aips.core.clock import ManualClock
from aips.core.models import ActionRequest, Level, Risk, Severity
from aips.core.policy import ApprovalQueue, AuthorizationPolicy, Outcome, PolicyConfig


class AuditTests(unittest.TestCase):
    def test_chain_verifies_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit.jsonl"
            led = AuditLedger(p, key=b"k" * 32, clock=ManualClock())
            for i in range(5):
                led.append("L3", "action.executed", {"i": i})
            self.assertEqual(led.verify()[0], True)
            self.assertTrue(AuditLedger.verify_file(p, b"k" * 32)[0])
            lines = p.read_text().splitlines()
            rec = json.loads(lines[2])
            rec["payload"]["i"] = 99
            lines[2] = json.dumps(rec, sort_keys=True)
            p.write_text("\n".join(lines) + "\n")
            ok, bad, reason = AuditLedger.verify_file(p, b"k" * 32)
            self.assertFalse(ok)
            self.assertEqual(bad, 3)
            self.assertIn("modified", reason)

    def test_wrong_key_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.jsonl"
            led = AuditLedger(p, key=b"right", clock=ManualClock())
            led.append("x", "e", {})
            self.assertFalse(AuditLedger.verify_file(p, b"wrong")[0])

    def test_deleted_record_breaks_chain(self):
        led = AuditLedger(clock=ManualClock())
        for i in range(3):
            led.append("a", "e", {"i": i})
        del led._records[1]
        self.assertFalse(led.verify()[0])


class BusTests(unittest.TestCase):
    def test_wildcards_and_isolation(self):
        bus = EventBus()
        got = []
        bus.subscribe("incident.*", lambda t, p: got.append(t))
        bus.subscribe("#", lambda t, p: (_ for _ in ()).throw(RuntimeError("boom")))
        bus.publish("incident.opened", 1)
        bus.publish("finding.l1", 2)
        self.assertEqual(got, ["incident.opened"])
        self.assertEqual(len(bus.dead_letters), 2)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = ManualClock()
        self.policy = AuthorizationPolicy(PolicyConfig(), clock=self.clock)

    def req(self, kind, target="api", level=Level.L3_DECISION):
        return ActionRequest(kind, target, requested_by=level)

    def test_unknown_and_level(self):
        self.assertEqual(self.policy.evaluate(self.req("rm.rf")).outcome, Outcome.DENY)
        self.assertEqual(self.policy.evaluate(self.req("host.isolate", level=Level.L2_EVALUATION)).outcome,
                         Outcome.DENY)
        self.assertEqual(self.policy.evaluate(self.req("service.restart", level=Level.L2_EVALUATION)).outcome,
                         Outcome.ALLOW)

    def test_high_risk_requires_two_approvers(self):
        d = self.policy.evaluate(self.req("host.isolate"))
        self.assertEqual(d.outcome, Outcome.REQUIRE_APPROVAL)
        self.assertEqual(d.approvals_required, 2)

    def test_always_approve_and_protected(self):
        self.assertEqual(self.policy.evaluate(self.req("package.upgrade")).outcome, Outcome.REQUIRE_APPROVAL)
        self.assertEqual(self.policy.evaluate(self.req("identity.freeze", "break-glass-admin")).outcome,
                         Outcome.REQUIRE_APPROVAL)

    def test_critical_asset(self):
        self.assertEqual(self.policy.evaluate(self.req("config.restore_baseline"), 5).outcome,
                         Outcome.REQUIRE_APPROVAL)
        self.assertEqual(self.policy.evaluate(self.req("config.restore_baseline"), 4).outcome, Outcome.ALLOW)

    def test_rate_limit_protects_against_repair_loops(self):
        r = self.req("service.restart")
        for _ in range(6):
            self.assertEqual(self.policy.evaluate(r).outcome, Outcome.ALLOW)
            self.policy.record_execution(r)
        self.assertEqual(self.policy.evaluate(r).outcome, Outcome.REQUIRE_APPROVAL)
        self.clock.advance(3601)
        self.assertEqual(self.policy.evaluate(r).outcome, Outcome.ALLOW)

    def test_kill_switch(self):
        self.policy.kill_switch = True
        self.assertEqual(self.policy.evaluate(self.req("service.restart")).outcome, Outcome.REQUIRE_APPROVAL)
        self.assertEqual(self.policy.evaluate(self.req("notify.humans")).outcome, Outcome.ALLOW)

    def test_approval_queue_distinct_approvers_and_expiry(self):
        q = ApprovalQueue(self.clock)
        a = q.submit(self.req("host.isolate"), "test", 2)
        self.assertIs(q.submit(self.req("host.isolate"), "dup", 2), a)
        q.approve(a.id, "alice")
        with self.assertRaises(ValueError):
            q.approve(a.id, "alice")
        q.approve(a.id, "bob")
        self.assertEqual(a.status.value, "approved")
        b = q.submit(self.req("package.upgrade", "x"), "t")
        self.clock.advance(5 * 3600)
        self.assertEqual(q.pending(), [])
        self.assertEqual(b.status.value, "expired")

    def test_severity_helpers(self):
        self.assertEqual(Severity.parse("high"), Severity.HIGH)
        self.assertEqual(Severity.CRITICAL.bump(1), Severity.CRITICAL)
        self.assertEqual(Severity.INFO.bump(-1), Severity.INFO)
        self.assertEqual(Risk.HIGH > Risk.MEDIUM, True)


if __name__ == "__main__":
    unittest.main()
