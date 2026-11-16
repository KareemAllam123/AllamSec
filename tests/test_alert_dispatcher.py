
"""Tests for persistent AllamSec notifications."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.alert_dispatcher import (
    dispatch_alerts,
    get_notification_history,
    initialize_notifications,
)
from database.db_manager import (
    initialize_database,
    save_alerts,
)


class TestAlertDispatcher(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "test.db"

        initialize_database(self.db_path)
        initialize_notifications(self.db_path)

        self.alert = {
            "alert_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "risk_score": 85,
            "source_ip": "192.168.1.50",
            "username": "admin",
            "description": "Repeated failed logins",
            "first_attempt": "2026-11-09T10:00:00",
            "last_attempt": "2026-11-09T10:01:00",
        }

        save_alerts([self.alert], db_path=self.db_path)

    def test_preview_created(self):
        result = dispatch_alerts(
            [self.alert],
            db_path=self.db_path,
        )

        self.assertEqual(result["previewed"], 1)

        history = get_notification_history(self.db_path)

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["status"], "PREVIEW")

    def test_duplicate_prevention(self):
        dispatch_alerts([self.alert], db_path=self.db_path)
        dispatch_alerts([self.alert], db_path=self.db_path)

        history = get_notification_history(self.db_path)

        self.assertEqual(len(history), 1)

    def test_email_sent(self):
        with patch(
            "app.alert_dispatcher.send_email_notification",
            return_value=True,
        ) as mock_send:
            result = dispatch_alerts(
                [self.alert],
                db_path=self.db_path,
                email_enabled=True,
            )

        self.assertEqual(result["sent"], 1)
        mock_send.assert_called_once()

        history = get_notification_history(self.db_path)
        self.assertEqual(history[0]["status"], "SENT")

    def test_sent_email_not_repeated(self):
        with patch(
            "app.alert_dispatcher.send_email_notification",
            return_value=True,
        ) as mock_send:
            dispatch_alerts(
                [self.alert],
                db_path=self.db_path,
                email_enabled=True,
            )
            dispatch_alerts(
                [self.alert],
                db_path=self.db_path,
                email_enabled=True,
            )

        self.assertEqual(mock_send.call_count, 1)

    def test_failed_email_recorded(self):
        with patch(
            "app.alert_dispatcher.send_email_notification",
            side_effect=RuntimeError("SMTP unavailable"),
        ):
            result = dispatch_alerts(
                [self.alert],
                db_path=self.db_path,
                email_enabled=True,
            )

        self.assertEqual(result["failed"], 1)

        history = get_notification_history(self.db_path)
        self.assertEqual(history[0]["status"], "FAILED")

    def test_failed_email_retry(self):
        with patch(
            "app.alert_dispatcher.send_email_notification",
            side_effect=RuntimeError("SMTP unavailable"),
        ):
            dispatch_alerts(
                [self.alert],
                db_path=self.db_path,
                email_enabled=True,
            )

        with patch(
            "app.alert_dispatcher.send_email_notification",
            return_value=True,
        ):
            result = dispatch_alerts(
                [self.alert],
                db_path=self.db_path,
                email_enabled=True,
            )

        self.assertEqual(result["sent"], 1)

        history = get_notification_history(self.db_path)
        self.assertEqual(history[0]["status"], "SENT")
        self.assertEqual(history[0]["attempts"], 2)

    def test_low_severity_ignored(self):
        low = dict(
            self.alert,
            severity="LOW",
            risk_score=15,
        )

        result = dispatch_alerts(
            [low],
            db_path=self.db_path,
        )

        self.assertEqual(result["eligible"], 0)

    def test_unsaved_alert_rejected(self):
        unsaved = dict(
            self.alert,
            source_ip="10.0.0.200",
        )

        with self.assertRaises(RuntimeError):
            dispatch_alerts(
                [unsaved],
                db_path=self.db_path,
            )

    def test_empty_alerts(self):
        result = dispatch_alerts(
            [],
            db_path=self.db_path,
        )

        self.assertEqual(result["eligible"], 0)

    def test_history_limit(self):
        with self.assertRaises(ValueError):
            get_notification_history(
                self.db_path,
                limit=0,
            )


if __name__ == "__main__":
    unittest.main()
