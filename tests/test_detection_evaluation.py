import unittest

from aips.core.models import Category, Disposition, Finding, Severity
from aips.evaluation.escalation import EscalationRouter
from aips.evaluation.evaluator import Level2Evaluator, MaintenanceWindow
from aips.evaluation.learning import OutcomeMemory
from aips.core.models import Level
from aips.monitoring.detectors import (AnomalyDetector, CapacityForecastDetector, CertificateExpiryDetector,
                                       DetectionContext, DriftDetector, HealthDetector, MetricHistory,
                                       PortExposureDetector, ThresholdDetector)
from aips.repair.baseline import DesiredStateStore, diff_values
from aips.telemetry.inventory import Asset, Certificate, Inventory
from aips.telemetry.sources import MetricSample, Observation


def inv():
    return Inventory([Asset("db", "database", 5), Asset("api", "service", 4, ["db"], allowed_ports=[443]),
                      Asset("web", "service", 3, ["api"])])


def ctx(now=1000.0, store=None, history=None, inventory=None):
    return DetectionContext(inventory or inv(), store or DesiredStateStore(), history or MetricHistory(), now)


class DetectorTests(unittest.TestCase):
    def test_health_confidence_grows(self):
        d = HealthDetector()
        c1 = d.detect(Observation(0, service_up={"api": False}), ctx())[0].confidence
        c2 = d.detect(Observation(0, service_up={"api": False}), ctx())[0].confidence
        self.assertLess(c1, c2)
        self.assertEqual(d.detect(Observation(0, service_up={"api": True}), ctx()), [])

    def test_threshold_requires_consecutive_cycles(self):
        d = ThresholdDetector()
        obs = Observation(0, metrics=[MetricSample("api", "error_rate", 0.1, 0)])
        self.assertFalse([f for f in d.detect(obs, ctx()) if f.signal == "error_rate_high"])
        self.assertTrue([f for f in d.detect(obs, ctx()) if f.signal == "error_rate_high"])

    def test_criticality_bumps_severity(self):
        d = HealthDetector()
        f = d.detect(Observation(0, service_up={"db": False}), ctx())[0]
        self.assertEqual(f.severity, Severity.CRITICAL)

    def test_forecast_fires_before_threshold(self):
        h = MetricHistory()
        d = CapacityForecastDetector(min_points=5)
        out = []
        for i in range(8):
            v = 50 + i * 1.0
            h.add("api", "disk_used_pct", i * 30.0, v)
            out = d.detect(Observation(i * 30.0, metrics=[MetricSample("api", "disk_used_pct", v, i * 30.0)]),
                           ctx(i * 30.0, history=h))
        self.assertTrue(out)
        self.assertEqual(out[0].signal, "disk_forecast")
        self.assertLess(out[0].evidence[0].data["current"], 90)

    def test_drift_security_sensitive(self):
        s = DesiredStateStore()
        s.capture("api", {"tls": {"enabled": True}, "log_level": "info"})
        d = DriftDetector(s)
        f = d.detect(Observation(0, configs={"api": {"tls": {"enabled": False}, "log_level": "info"}}),
                     ctx(store=s))[0]
        self.assertEqual(f.category, Category.SECURITY)
        f2 = d.detect(Observation(0, configs={"api": {"tls": {"enabled": True}, "log_level": "debug2"}}),
                      ctx(store=s))[0]
        self.assertEqual(f2.category, Category.CONFIGURATION)

    def test_diff_values(self):
        diffs = diff_values({"a": 1, "b": {"c": 2}}, {"a": 1, "b": {"c": 3}, "d": 4})
        self.assertEqual({(d.path, d.change) for d in diffs}, {("b.c", "modified"), ("d", "added")})

    def test_ports_and_certs(self):
        f = PortExposureDetector().detect(Observation(0, open_ports={"api": [443, 4444]}), ctx())
        self.assertEqual([x.tags["port"] for x in f], ["4444"])
        i = Inventory([Asset("api", "service", certificates=[Certificate("c", 1000 + 3 * 86400)])])
        f = CertificateExpiryDetector().detect(Observation(0), ctx(1000, inventory=i))
        self.assertEqual(f[0].severity, Severity.HIGH)

    def test_anomaly_detector_and_level_shift(self):
        d = AnomalyDetector(warmup=10, level_shift_after=5)
        c = ctx()
        for i in range(30):
            d.detect(Observation(i, metrics=[MetricSample("api", "latency_p95_ms", 100 + (i % 3), i)]), c)
        hits = d.detect(Observation(31, metrics=[MetricSample("api", "latency_p95_ms", 900, 31)]), c)
        self.assertTrue(hits)
        for i in range(10):
            last = d.detect(Observation(40 + i, metrics=[MetricSample("api", "latency_p95_ms", 900, 40 + i)]), c)
        self.assertEqual(last, [])   # new normal absorbed


def finding(asset="api", sev=Severity.MEDIUM, conf=0.8, signal="error_rate_high", cat=Category.AVAILABILITY,
            det="l1.threshold", t=1000.0):
    return Finding(det, cat, sev, conf, asset, "t", created_at=t, signal=signal)


class EvaluatorTests(unittest.TestCase):
    def ev(self, **kw):
        return Level2Evaluator(inv(), OutcomeMemory(), l2_signals=["error_rate_high", "service_down"], **kw)

    def test_dismiss_low_confidence(self):
        v = self.ev().evaluate([finding(conf=0.1)], 1000)[0]
        self.assertEqual(v.disposition, Disposition.DISMISS)

    def test_low_severity_needs_persistence(self):
        e = self.ev()
        self.assertEqual(e.evaluate([finding(sev=Severity.LOW, signal="x")], 1000)[0].disposition, Disposition.MONITOR)

    def test_handle_and_escalate(self):
        e = self.ev()
        self.assertEqual(e.evaluate([finding()], 1000)[0].disposition, Disposition.HANDLE)
        self.assertEqual(e.evaluate([finding(sev=Severity.HIGH, signal="y")], 1000)[0].disposition,
                         Disposition.ESCALATE)

    def test_root_cause_symptom(self):
        e = self.ev()
        e.observe_context([finding("db", Severity.HIGH, signal="service_down")], 1000)
        v = e.evaluate([finding("api", Severity.HIGH, signal="error_rate_critical")], 1000)[0]
        self.assertEqual(v.disposition, Disposition.MONITOR)
        self.assertEqual(v.root_cause_asset, "db")

    def test_maintenance_and_suppression(self):
        e = self.ev()
        e.add_maintenance(MaintenanceWindow("ap*", 900, 1100, "patching"))
        self.assertEqual(e.evaluate([finding(sev=Severity.HIGH)], 1000)[0].disposition, Disposition.MONITOR)
        e2 = self.ev()
        f = finding()
        e2.suppress(f.fingerprint)
        self.assertEqual(e2.evaluate([f], 1000)[0].disposition, Disposition.DISMISS)

    def test_transient_case_expires_as_dismissed(self):
        e = self.ev()
        e.evaluate([finding(sev=Severity.LOW, signal="blip")], 1000)
        out = e.evaluate([], 1000 + 500)
        self.assertEqual(out[0].disposition, Disposition.DISMISS)

    def test_learning_shifts_confidence(self):
        m = OutcomeMemory()
        f = finding()
        for _ in range(10):
            m.record(f.fingerprint, f.detector, true_positive=False)
        self.assertLess(m.confidence_factor(f.fingerprint, f.detector), 0.75)
        e = Level2Evaluator(inv(), m, l2_signals=["error_rate_high"])
        self.assertLess(e.evaluate([f], 1000)[0].confidence, 0.8)

    def test_router_bypass(self):
        r = EscalationRouter()
        self.assertEqual(r.route(finding(sev=Severity.CRITICAL))[0], Level.L3_DECISION)
        self.assertEqual(r.route(finding(sev=Severity.HIGH, conf=0.95))[0], Level.L3_DECISION)
        self.assertEqual(r.route(finding(sev=Severity.HIGH, conf=0.8, cat=Category.SECURITY))[0], Level.L3_DECISION)
        self.assertEqual(r.route(finding(sev=Severity.MEDIUM))[0], Level.L2_EVALUATION)


if __name__ == "__main__":
    unittest.main()
