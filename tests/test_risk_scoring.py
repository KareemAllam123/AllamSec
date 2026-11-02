import unittest

from detection.risk_scoring import (
    calculate_risk_score,
    classify_severity,
    score_alert,
    score_alerts,
)


class TestRiskScoring(unittest.TestCase):

    def test_low_severity(self):
        self.assertEqual(classify_severity(10), "LOW")

    def test_medium_severity(self):
        self.assertEqual(classify_severity(35), "MEDIUM")

    def test_high_severity(self):
        self.assertEqual(classify_severity(65), "HIGH")

    def test_critical_severity(self):
        self.assertEqual(classify_severity(95), "CRITICAL")

    def test_severity_boundaries(self):
        self.assertEqual(classify_severity(24), "LOW")
        self.assertEqual(classify_severity(25), "MEDIUM")
        self.assertEqual(classify_severity(49), "MEDIUM")
        self.assertEqual(classify_severity(50), "HIGH")
        self.assertEqual(classify_severity(79), "HIGH")
        self.assertEqual(classify_severity(80), "CRITICAL")

    def test_invalid_negative_score(self):
        with self.assertRaises(ValueError):
            classify_severity(-1)

    def test_invalid_score_above_100(self):
        with self.assertRaises(ValueError):
            classify_severity(101)

    def test_brute_force_score(self):
        alert = {
            "alert_type": "POSSIBLE_BRUTE_FORCE",
            "failed_attempts": 5,
        }

        self.assertEqual(calculate_risk_score(alert), 65)

    def test_port_scan_score(self):
        alert = {
            "alert_type": "POSSIBLE_PORT_SCAN",
            "unique_ports": 10,
        }

        self.assertEqual(calculate_risk_score(alert), 70)

    def test_account_compromise_score(self):
        alert = {
            "alert_type": "POSSIBLE_ACCOUNT_COMPROMISE",
            "failed_attempts": 5,
        }

        self.assertEqual(calculate_risk_score(alert), 95)

    def test_risk_score_capped_at_100(self):
        alert = {
            "alert_type": "POSSIBLE_PORT_SCAN",
            "unique_ports": 1000,
        }

        self.assertEqual(calculate_risk_score(alert), 80)

    def test_unknown_alert_type(self):
        alert = {"alert_type": "UNKNOWN"}

        with self.assertRaises(ValueError):
            calculate_risk_score(alert)

    def test_score_alert_adds_risk_score(self):
        alert = {
            "alert_type": "POSSIBLE_BRUTE_FORCE",
            "failed_attempts": 5,
        }

        result = score_alert(alert)

        self.assertEqual(result["risk_score"], 65)
        self.assertEqual(result["severity"], "HIGH")

    def test_original_alert_unchanged(self):
        alert = {
            "alert_type": "POSSIBLE_BRUTE_FORCE",
            "failed_attempts": 5,
        }

        score_alert(alert)

        self.assertNotIn("risk_score", alert)

    def test_alerts_sorted_by_risk(self):
        alerts = [
            {
                "alert_type": "POSSIBLE_BRUTE_FORCE",
                "failed_attempts": 5,
            },
            {
                "alert_type": "POSSIBLE_ACCOUNT_COMPROMISE",
                "failed_attempts": 5,
            },
            {
                "alert_type": "POSSIBLE_PORT_SCAN",
                "unique_ports": 10,
            },
        ]

        results = score_alerts(alerts)

        self.assertEqual(
            [alert["risk_score"] for alert in results],
            [95, 70, 65],
        )

    def test_empty_alerts(self):
        self.assertEqual(score_alerts([]), [])


if __name__ == "__main__":
    unittest.main()