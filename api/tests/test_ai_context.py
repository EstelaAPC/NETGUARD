import os
import sys
import unittest


sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import (
    build_host_findings_summary,
    build_host_operational_assessment,
    build_low_relevance_signal_entries,
    render_host_context_digest,
)


class AIContextTest(unittest.TestCase):
    def test_resolved_incident_is_not_reported_as_open(self):
        context = {
            "time_window": {
                "to": "2026-06-03T22:52:00+00:00",
            },
            "host": {
                "name": "Switch Lab",
                "health_status": "degraded",
                "operational_posture": "attention",
            },
            "active_incidents": [],
            "recent_incidents": [
                {
                    "incident_type": "syslog_loop_gi0_5",
                    "severity": "critical",
                    "status": "resolved",
                    "title": "[NetGuard] Problema detectado",
                    "resolved_at": "2026-06-03T16:53:22+00:00",
                }
            ],
            "signal_groups": {},
            "recent_predictions": [],
        }

        summary = build_host_findings_summary(context)

        self.assertNotIn("aberto", str(summary.get("primary_issue") or "").lower())
        self.assertEqual(summary["supporting_signals"], [])
        self.assertTrue(any("resolved" in item for item in summary["historical_signals"]))

    def test_score_zero_prediction_is_not_an_anomaly_signal(self):
        context = {
            "time_window": {"to": "2026-06-03T22:52:00+00:00"},
            "host": {"health_status": "healthy"},
            "active_incidents": [],
            "recent_incidents": [],
            "signal_groups": {},
            "recent_predictions": [
                {
                    "metric": "snmp.if.in_discards.delta",
                    "severity": "info",
                    "score": 0,
                    "if_name": "Gi0/1",
                    "ts": "2026-06-03T22:51:00+00:00",
                }
            ],
        }

        summary = build_host_findings_summary(context)
        low_relevance = build_low_relevance_signal_entries(context["recent_predictions"])
        assessment = build_host_operational_assessment(context)

        self.assertEqual(summary["problems"], [])
        self.assertEqual(summary["supporting_signals"], [])
        self.assertEqual(low_relevance, [])
        self.assertNotIn("Anomalia SNMP", str(assessment))

    def test_old_loop_signals_are_historical_without_active_incident(self):
        context = {
            "time_window": {"to": "2026-06-03T22:52:00+00:00"},
            "host": {"health_status": "degraded"},
            "active_incidents": [],
            "recent_incidents": [],
            "signal_groups": {
                "loop_storm": [
                    {
                        "signal_type": "loop_storm",
                        "focus": "Gi0/1",
                        "count": 20,
                        "last_seen": "2026-06-03T16:36:53+00:00",
                        "messages": ["Broadcast storm detected on Interface Gi0/1"],
                    }
                ],
            },
            "recent_predictions": [],
        }

        summary = build_host_findings_summary(context)
        assessment = build_host_operational_assessment(context)
        digest = render_host_context_digest({**context, "findings_summary": summary, "operational_assessment": assessment})

        self.assertEqual(summary["problems"], [])
        self.assertEqual(summary["supporting_signals"], [])
        self.assertTrue(any("Historico recente" in item for item in summary["historical_signals"]))
        self.assertNotIn("risco operacional relevante", str(assessment["state"]).lower())
        self.assertIn("Nenhum incidente aberto", digest)
        self.assertIn("nao classificar como problema ativo", digest)
        self.assertNotIn("Sinais de apoio:\n- Historico recente", digest)


if __name__ == "__main__":
    unittest.main()
