"""Layer mesh, persistent experience store and strategy exploration."""

import logging
import tempfile
import unittest
from pathlib import Path

from aips.core.audit import AuditLedger
from aips.core.clock import ManualClock
from aips.core.mesh import LayerMesh
from aips.core.models import Category, Level
from aips.decision.playbooks import Check, Playbook, PlaybookLibrary, Step
from aips.decision.strategies import StrategySelector
from aips.experience.store import Episode, ExperienceStore, reward_for
from aips.sim.scenarios import run_scenario

logging.disable(logging.CRITICAL)


class MeshTests(unittest.TestCase):
    def test_call_discovery_and_stats(self):
        m = LayerMesh()
        m.register("L1", "rescan", lambda p: {"asset": p["asset"], "keys": []}, "re-scan")
        self.assertTrue(m.has("L1", "rescan"))
        r = m.call("L3", "L1", "rescan", {"asset": "api"})
        self.assertTrue(r.ok)
        self.assertEqual(r.value["asset"], "api")
        self.assertEqual(m.stats["L1.rescan"], 1)
        self.assertEqual(m.recent()[0]["caller"], "L3")
        self.assertFalse(m.call("L3", "L9", "nope").ok)

    def test_loops_and_depth_are_refused(self):
        m = LayerMesh(max_depth=3)
        m.register("A", "ping", lambda p: m.call("A", "B", "pong", p).value)
        m.register("B", "pong", lambda p: m.call("B", "A", "ping", p).error)
        r = m.call("x", "A", "ping", {"n": 1})
        self.assertTrue(r.ok)
        self.assertIn("re-entrant", r.value)
        self.assertEqual(m.refused["loop"], 1)

        def deep(p):
            r = m.call("C", "C", "deep", {"n": p["n"] + 1})
            return r.error or r.value          # pass the innermost refusal back up
        m.register("C", "deep", deep)
        self.assertIn("depth", m.call("x", "C", "deep", {"n": 0}).value)

    def test_failures_are_contained_and_mutations_audited(self):
        led = AuditLedger(clock=ManualClock())
        m = LayerMesh(led)
        m.register("L3", "boom", lambda p: 1 / 0, mutating=True)
        r = m.call("L1", "L3", "boom")
        self.assertFalse(r.ok)
        self.assertIn("ZeroDivisionError", r.error)
        self.assertEqual(led.records("mesh.call")[0].payload["ok"], False)


class ExperienceTests(unittest.TestCase):
    def ep(self, i, strategy, outcome, asset="api", t=1000.0, run="r1"):
        return Episode(f"{run}:{i}", f"INC-{i}", asset, "capacity", "overload", strategy, t, outcome,
                       reward_for(outcome, 2, 60), t + 60, run_id=run)

    def test_persistence_across_instances(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "exp.db"
            s = ExperienceStore(db, run_id="r1")
            s.record_episode(self.ep(1, "scale-first", "resolved"), [{"kind": "service.scale_out", "success": True}])
            s.record("fp1", "l1.threshold", True)
            s.note(1000, "chronic:api:overload", "3 in 7 days")
            s.close()
            s2 = ExperienceStore(db, run_id="r2")
            try:
                self.assertEqual(s2.summary()["episodes"], 1)
                self.assertEqual(s2.actions("r1:1")[0]["kind"], "service.scale_out")
                self.assertGreater(s2.precision("fp1", "l1.threshold"), 0.5)
                self.assertTrue(s2.has_note("chronic:api:overload", 0))
            finally:
                s2.close()

    def test_stats_relapse_recurrence_similar(self):
        s = ExperienceStore()
        s.record_episode(self.ep(1, "a", "resolved", t=100))
        s.record_episode(self.ep(2, "a", "resolved", t=200))
        s.record_episode(self.ep(3, "b", "resolved", t=300))
        s.mark_relapse("r1:3")
        s.record_episode(self.ep(4, "a", "failed", asset="other", t=400))
        st = s.strategy_stats("overload", "api")
        self.assertGreater(st["a"]["mean_reward"], st["b"]["mean_reward"])
        self.assertEqual(s.episodes(limit=10)[0].id, "r1:4")
        self.assertEqual([e.outcome for e in s.episodes(signal="overload") if e.strategy == "b"], ["relapsed"])
        self.assertEqual(s.recurrence("api", "overload", 150), 2)
        self.assertEqual(s.similar("overload", "api", 2)[0]["asset"], "api")
        self.assertEqual(reward_for("failed", 0, 0), 0.0)
        self.assertGreater(reward_for("resolved", 1, 30), reward_for("resolved", 6, 1800))


class SelectorTests(unittest.TestCase):
    def pbs(self):
        def pb(name, priority=3):
            return Playbook(name, ["overload"], Level.L2_EVALUATION, [Step("service.scale_out")], [Check("signal_clear")],
                            priority=priority)
        return [pb("p1"), pb("p2"), pb("p3")]

    def test_untried_first_then_exploit(self):
        s = ExperienceStore()
        sel = StrategySelector(s, seed=1)
        c = sel.choose(self.pbs(), "overload", "api")
        self.assertEqual(c.mode, "explore-untried")
        for i in range(8):
            s.record_episode(Episode(f"g{i}", f"I{i}", "api", "capacity", "overload", "p2", i, "resolved", 0.95))
            s.record_episode(Episode(f"b{i}", f"J{i}", "api", "capacity", "overload", "p1", i, "failed", 0.0))
            s.record_episode(Episode(f"c{i}", f"K{i}", "api", "capacity", "overload", "p3", i, "relapsed", 0.2))
        picks = [sel.choose(self.pbs(), "overload", "api").playbook.name for _ in range(40)]
        self.assertGreater(picks.count("p2"), 32)

    def test_exclude_and_no_exploration_for_containment(self):
        sel = StrategySelector(ExperienceStore(), seed=1)
        self.assertEqual(sel.choose(self.pbs(), "overload", "api", exclude=["p1", "p2"]).playbook.name, "p3")
        self.assertIsNone(sel.choose(self.pbs(), "overload", "api", exclude=["p1", "p2", "p3"]))
        contain = [Playbook(n, ["x"], Level.L3_DECISION, [], [], priority=0) for n in ("c1", "c2")]
        self.assertFalse(contain[0].explorable)
        self.assertEqual(sel.choose(contain, "x", "api").mode, "fixed")

    def test_library_has_variants(self):
        lib = PlaybookLibrary()
        names = [p.name for p in lib.candidates("overload", Category.CAPACITY)]
        self.assertEqual(names[0], "overload-protection")
        self.assertIn("scale-first", names)
        self.assertEqual(len(lib.candidates("config_drift", Category.CONFIGURATION)), 1)


class LearningScenarioTests(unittest.TestCase):
    def test_new_scenarios_pass(self):
        for name in ("strategy_learning", "transient_drift", "experience_carryover"):
            for seed in (7, 3):
                with self.subTest(scenario=name, seed=seed):
                    r, _ = run_scenario(name, seed)
                    self.assertTrue(r.passed, [f"{c.name}: {c.detail}" for c in r.checks if not c.ok])


if __name__ == "__main__":
    unittest.main()
