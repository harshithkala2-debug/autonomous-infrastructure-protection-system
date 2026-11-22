"""Valves, identity guard, backup/vault, executor."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from aips.backup.manager import BackupManager, BackupPolicy, shannon_entropy
from aips.backup.store import IntegrityError, ObjectStore
from aips.backup.vault import RetentionLocked, Vault, VaultAccessDenied, VaultConfig
from aips.core.models import ActionRequest, Level
from aips.identity.guard import AccessEvent, Identity, IdentityGuard, PermissionBoundary, PermissionRule
from aips.repair.executor import ActionDispatcher, CommandAdapter, CommandTemplate, RecordingAdapter
from aips.traffic.valves import Priority, TrafficController, ValveMode


class ValveTests(unittest.TestCase):
    def test_floor_shedding_and_ramp(self):
        tc = TrafficController()
        v = tc.throttle("api", "ingress", 0.0, "test", 0)
        self.assertEqual(v.position, 0.1)          # autonomous floor
        self.assertEqual(v.mode, ValveMode.CRITICAL_ONLY)
        self.assertTrue(v.admits_priority(Priority.CRITICAL))
        self.assertFalse(v.admits_priority(Priority.BULK))
        tc.throttle("api", "ingress", 0.3, "test", 0)
        self.assertEqual(tc.position("api", "ingress"), 0.1)   # more restrictive wins
        tc.release("api", "ok", 0)
        tc.tick(1, lambda a: True)
        self.assertAlmostEqual(tc.position("api", "ingress"), 0.35)
        tc.tick(2, lambda a: False)                # regression: multiplicative back-off
        self.assertAlmostEqual(tc.position("api", "ingress"), 0.175)
        for t in range(3, 10):
            tc.tick(t, lambda a: True)
        self.assertEqual(tc.position("api", "ingress"), 1.0)

    def test_token_bucket(self):
        tc = TrafficController()
        v = tc.throttle("api", "internal", 0.5, "t", 0)
        v.capacity_rps = 10
        admitted = sum(v.admit(0.0) for _ in range(20))
        self.assertLessEqual(admitted, 6)
        self.assertTrue(v.admit(100.0))

    def test_both_valves(self):
        tc = TrafficController()
        tc.throttle("db", "both", 0.5, "t", 0)
        self.assertEqual(tc.position("db", "ingress"), 0.5)
        self.assertEqual(tc.position("db", "internal"), 0.5)
        with self.assertRaises(ValueError):
            tc.valve("db", "sideways")


class IdentityTests(unittest.TestCase):
    def guard(self):
        g = IdentityGuard()
        g.register(Identity("svc", "service"), PermissionBoundary(
            allow=[PermissionRule("storage.read", "bucket/reports/*")], deny=[PermissionRule("iam.*")],
            source_networks=["10.0.0.0/8"], max_rate_per_min=1000))
        for i in range(30):
            g.evaluate(AccessEvent("svc", "storage.read", f"bucket/reports/r{i}", 1000 + i, "10.1.1.1"))
        return g

    def test_normal_activity_allowed_and_learned(self):
        g = self.guard()
        d = g.evaluate(AccessEvent("svc", "storage.read", "bucket/reports/x", 2000, "10.1.1.1"))
        self.assertTrue(d.allowed)
        self.assertIsNone(d.finding)
        self.assertEqual(g.profiles["svc"].events, 31)

    def test_boundary_violation_denied_and_high_risk(self):
        g = self.guard()
        d = g.evaluate(AccessEvent("svc", "secrets.read", "vault/prod", 2000, "203.0.113.9"))
        self.assertFalse(d.allowed)
        self.assertEqual(d.finding.signal, "boundary_violation")
        self.assertGreater(d.risk, 0.75)
        self.assertEqual(g.profiles["svc"].events, 30)       # risky events are never learned

    def test_unusual_but_permitted_is_not_malicious(self):
        g = self.guard()
        d = g.evaluate(AccessEvent("svc", "storage.read", "bucket/reports/new", 2000, "10.200.0.1"))
        self.assertTrue(d.allowed)
        self.assertTrue(d.finding is None or d.finding.severity.name in ("LOW", "MEDIUM"))

    def test_failure_burst(self):
        g = self.guard()
        d = None
        for i in range(5):
            d = g.evaluate(AccessEvent("svc", "storage.read", "bucket/reports/a", 3000 + i, "10.1.1.1", success=False))
        self.assertEqual(d.finding.signal, "credential_misuse")

    def test_freeze_revoke_appeal(self):
        g = self.guard()
        g.evaluate(AccessEvent("svc", "storage.read", "bucket/reports/a", 3000, "10.1.1.1", session_id="s1"))
        g.freeze("svc", "test", 3001)
        self.assertFalse(g.evaluate(AccessEvent("svc", "storage.read", "bucket/reports/a", 3002, "10.1.1.1")).allowed)
        self.assertEqual(g.revoke_sessions("svc"), 1)
        a = g.submit_appeal("svc", "owner", "legit", 3002)
        with self.assertRaises(ValueError):
            g.review_appeal(a.id, "owner", True, 3003)          # cannot review own appeal
        fps = []
        g.on_false_positive = fps.append
        g.review_appeal(a.id, "sec", True, 3004, allow_rule=PermissionRule("storage.write", "bucket/reports/*"))
        self.assertFalse(g.is_frozen("svc"))
        self.assertEqual(fps, ["svc"])
        self.assertFalse(g.evaluate(AccessEvent("svc", "storage.read", "bucket/reports/a", 3005, "10.1.1.1",
                                                session_id="s1")).allowed)   # revoked session stays revoked
        self.assertTrue(g.evaluate(AccessEvent("svc", "storage.write", "bucket/reports/a", 3006, "10.1.1.1",
                                               session_id="s2")).allowed)

    def test_hours_wrap_midnight(self):
        b = PermissionBoundary(allowed_hours_utc=(22, 6))
        self.assertTrue(b.hour_ok(23))
        self.assertTrue(b.hour_ok(3))
        self.assertFalse(b.hour_ok(12))


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.main = root / "main"
        self.main.mkdir()
        for i in range(10):
            (self.main / f"f{i}.txt").write_text(f"file {i} " * 50)
        self.key = b"k" * 32
        self.vault = Vault(VaultConfig(str(root / "vault"), ["10.0.0.0/8"], 3600, "salt"), self.key)
        self.mgr = BackupManager(self.main, ObjectStore(root / "copy"), self.key, self.vault,
                                 BackupPolicy(min_files_for_guard=5), replication_ip="10.0.0.5")

    def tearDown(self):
        for dirpath, _, files in os.walk(self.tmp.name):
            for f in files:
                os.chmod(os.path.join(dirpath, f), 0o600)
        self.tmp.cleanup()

    def test_snapshot_replicate_restore(self):
        m = self.mgr.snapshot(1000)
        self.assertEqual(len(m.files), 10)
        self.assertEqual(self.mgr.replicate(1000)["replicated"], 1)
        (self.main / "f1.txt").write_text("changed")
        m2 = self.mgr.snapshot(2000)
        self.assertEqual(m2.parent, m.id)
        self.assertFalse(m2.suspect)
        with tempfile.TemporaryDirectory() as out:
            rep = self.mgr.restore(m.id, out)
            self.assertTrue(rep.verified)
            self.assertEqual((Path(out) / "f1.txt").read_text(), "file 1 " * 50)
        with tempfile.TemporaryDirectory() as out:
            self.assertTrue(self.mgr.restore("latest", out, from_vault=True, source_ip="10.0.0.5").verified)
        self.assertTrue(self.mgr.restore_drill(3000)["ok"])

    def test_corruption_detected(self):
        m = self.mgr.snapshot(1000)
        digest = next(iter(m.files.values())).sha256
        p = self.mgr.copy._path(digest)
        p.write_bytes(b"AIPS0garbage")
        with self.assertRaises(IntegrityError):
            self.mgr.copy.get(digest)
        self.assertEqual(self.mgr.verify()["copy_objects_corrupt"], 1)

    def test_manifest_tamper_rejected(self):
        m = self.mgr.snapshot(1000)
        m.files["f0.txt"].size = 1
        self.assertFalse(m.verify(self.key))

    def test_vault_gate_and_retention_lock(self):
        m = self.mgr.snapshot(1000)
        self.mgr.replicate(1000)
        with self.assertRaises(VaultAccessDenied):
            self.vault.snapshots("192.168.1.1")
        with self.assertRaises(VaultAccessDenied):
            self.vault.snapshots(None)
        with self.assertRaises(RetentionLocked):
            self.vault.delete_snapshot(m.id, "10.0.0.5", 1500)
        self.vault.delete_snapshot(m.id, "10.0.0.5", 1000 + 3601)
        self.assertEqual(self.vault.snapshots("10.0.0.5"), [])
        self.assertTrue(all("192.168" not in str(e) for e in self.vault.access_log))   # IP never logged

    def test_ransomware_guard_blocks_vault_replication(self):
        self.mgr.snapshot(1000)
        self.mgr.replicate(1000)
        for p in list(self.main.glob("*.txt"))[:6]:
            p.write_bytes(os.urandom(4096))
            p.rename(p.with_suffix(".txt.locked"))
        m = self.mgr.snapshot(2000)
        self.assertTrue(m.suspect)
        self.assertTrue(self.mgr.replication_held)
        f = self.mgr.drain_findings()
        self.assertEqual(f[0].signal, "mass_encryption")
        self.assertIn("held", self.mgr.replicate(2000)["reason"])
        self.assertEqual(self.mgr.latest().id, self.mgr.copy.manifests()[0].id)    # latest clean = pre-attack
        rep = self.mgr.restore("latest_clean", clean_target=True)
        self.assertTrue(rep.verified)
        self.assertFalse(list(self.main.glob("*.locked")))

    def test_entropy(self):
        self.assertLess(shannon_entropy(b"aaaa" * 100), 1)
        self.assertGreater(shannon_entropy(os.urandom(4096)), 7.5)

    def test_retention_plan(self):
        for d in range(40):
            (self.main / "f0.txt").write_text(f"v{d}")
            self.mgr.snapshot(1_700_000_000 + d * 86400)
        keep, delete = self.mgr.retention_plan()
        self.assertTrue(delete)
        self.assertLessEqual(len(keep), 24 + 7 + 4 + 6)
        self.mgr.prune()
        self.assertEqual(len(self.mgr.copy.manifests()), len(keep))


class ExecutorTests(unittest.TestCase):
    def test_command_adapter_refuses_injection(self):
        calls = []

        def runner(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "ok", "")

        ad = CommandAdapter({"service.restart": CommandTemplate(["systemctl", "restart", "{target}"])}, runner)
        self.assertTrue(ad.execute(ActionRequest("service.restart", "api")).success)
        self.assertEqual(calls[0], ["systemctl", "restart", "api"])
        bad = ad.execute(ActionRequest("service.restart", "api; rm -rf /"))
        self.assertFalse(bad.success)
        self.assertIn("unsafe", bad.detail)
        self.assertEqual(len(calls), 1)
        self.assertFalse(ad.execute(ActionRequest("host.isolate", "x")).success)

    def test_dispatcher_dry_run_and_handlers(self):
        rec = RecordingAdapter()
        d = ActionDispatcher(rec, lambda: 0.0, dry_run=True)
        r = d.execute(ActionRequest("service.restart", "api", requested_by=Level.L3_DECISION))
        self.assertTrue(r.dry_run)
        self.assertEqual(rec.calls, [])
        d.dry_run = False
        d.register("traffic.", lambda req: (True, "valve", None))
        self.assertEqual(d.execute(ActionRequest("traffic.throttle", "api")).detail, "valve")
        d.register("boom.x", lambda req: 1 / 0)
        self.assertFalse(d.execute(ActionRequest("boom.x", "api")).success)


if __name__ == "__main__":
    unittest.main()
