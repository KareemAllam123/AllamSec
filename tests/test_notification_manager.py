
"""Tests for AllamSec notification management."""

import unittest
from unittest.mock import patch

from app.notification_manager import (
    format_alert_message,
    notify_alerts,
    should_notify,
)


class TestNotificationManager(unittest.TestCase):

    def setUp(self):
        self.alert = {
            "alert_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "risk_score": 85,
        }

    def test_high_severity_eligible(self):
        self.assertTrue(
            should_notify(self.alert, "HIGH")
        )

    def test_low_severity_excluded(self):
        alert = dict(self.alert, severity="LOW")

        self.assertFalse(
            should_notify(alert, "HIGH")
        )

    def test_critical_severity_eligible(self):
        alert = dict(self.alert, severity="CRITICAL")

        self.assertTrue(
            should_notify(alert, "HIGH")
        )

    def test_invalid_minimum_severity(self):
        with self.assertRaises(ValueError):
            should_notify(self.alert, "INVALID")

    def test_unknown_alert_severity(self):
        alert = dict(self.alert, severity="UNKNOWN")

        self.assertFalse(
            should_notify(alert, "HIGH")
        )

    def test_message_contains_alert_details(self):
        message = format_alert_message(self.alert)

        self.assertIn("BRUTE_FORCE", message)
        self.assertIn("192.168.1.50", message)
        self.assertIn("HIGH", message)

    def test_preview_mode_does_not_send_email(self):
        with patch(
            "app.notification_manager.send_email_notification"
        ) as mock_send:
            result = notify_alerts(
                [self.alert],
                email_enabled=False,
            )

        mock_send.assert_not_called()

        self.assertEqual(
            result["eligible_alerts"],
            1,
        )

        self.assertEqual(
            result["sent_notifications"],
            0,
        )

    def test_email_notification_sent(self):
        with patch(
            "app.notification_manager.send_email_notification",
            return_value=True,
        ) as mock_send:
            result = notify_alerts(
                [self.alert],
                email_enabled=True,
            )

        mock_send.assert_called_once()

        self.assertEqual(
            result["sent_notifications"],
            1,
        )

    def test_email_failure_recorded(self):
        with patch(
            "app.notification_manager.send_email_notification",
            side_effect=RuntimeError("SMTP unavailable"),
        ):
            result = notify_alerts(
                [self.alert],
                email_enabled=True,
            )

        self.assertEqual(
            result["failed_notifications"],
            1,
        )

    def test_multiple_severity_filtering(self):
        alerts = [
            dict(self.alert, severity="LOW"),
            dict(self.alert, severity="MEDIUM"),
            dict(self.alert, severity="HIGH"),
            dict(self.alert, severity="CRITICAL"),
        ]

        result = notify_alerts(
            alerts,
            minimum_severity="HIGH",
            email_enabled=False,
        )

        self.assertEqual(
            result["eligible_alerts"],
            2,
        )


if __name__ == "__main__":
    unittest.main()
