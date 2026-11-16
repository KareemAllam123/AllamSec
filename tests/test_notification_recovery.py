
"""Tests for persistent notification recovery."""

import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from app.alert_dispatcher import (
    dispatch_alerts,
    get_notification_history,
    get_notification_summary,
    recover_stale_notifications,
)

from database.db_manager import (
    database_connection,
    initialize_database,
    save_alerts,
)


class TestNotificationRecovery(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "test.db"

        initialize_database(self.db_path)

        self.alert = {
            "alert_type": "POSSIBLE_BRUTE_FORCE",
            "severity": "HIGH",
            "risk_score": 85,
            "source_ip": "192.168.1.50",
            "target_account": "admin",
            "failed_attempts": 5,
            "first_attempt": "2026-11-10T12:00:00",
            "last_attempt": "2026-11-10T12:00:40",
            "time_window_seconds": 60,
            "description": "Five failed login attempts.",
        }

        save_alerts(
            [self.alert],
            db_path=self.db_path,
        )

    def dispatch(self, email_enabled=False, max_attempts=3):
        return dispatch_alerts(
            [self.alert],
            db_path=self.db_path,
            email_enabled=email_enabled,
            max_attempts=max_attempts,
        )

    def history(self):
        return get_notification_history(
            db_path=self.db_path,
        )[0]

    def test_preview_mode(self):
        result = self.dispatch()

        self.assertEqual(result["previewed"], 1)
        self.assertEqual(self.history()["status"], "PREVIEW")

    @patch("app.alert_dispatcher.send_email_notification")
    def test_successful_email(self, mock_send):
        result = self.dispatch(email_enabled=True)

        self.assertEqual(result["sent"], 1)
        self.assertEqual(self.history()["status"], "SENT")
        self.assertEqual(self.history()["attempts"], 1)
        mock_send.assert_called_once()

    @patch("app.alert_dispatcher.send_email_notification")
    def test_failed_email(self, mock_send):
        mock_send.side_effect = RuntimeError("SMTP unavailable")

        result = self.dispatch(email_enabled=True)

        self.assertEqual(result["failed"], 1)
        self.assertEqual(self.history()["status"], "FAILED")
        self.assertEqual(self.history()["attempts"], 1)

    @patch("app.alert_dispatcher.send_email_notification")
    def test_retry_after_failure(self, mock_send):
        mock_send.side_effect = [
            RuntimeError("Temporary failure"),
            True,
        ]

        self.dispatch(email_enabled=True)
        result = self.dispatch(email_enabled=True)

        self.assertEqual(result["sent"], 1)
        self.assertEqual(self.history()["status"], "SENT")
        self.assertEqual(self.history()["attempts"], 2)

    @patch("app.alert_dispatcher.send_email_notification")
    def test_maximum_attempts(self, mock_send):
        mock_send.side_effect = RuntimeError("SMTP unavailable")

        for _ in range(4):
            self.dispatch(
                email_enabled=True,
                max_attempts=3,
            )

        self.assertEqual(self.history()["attempts"], 3)
        self.assertEqual(self.history()["status"], "FAILED")
        self.assertEqual(mock_send.call_count, 3)

    @patch("app.alert_dispatcher.send_email_notification")
    def test_sent_email_not_resent(self, mock_send):
        self.dispatch(email_enabled=True)
        result = self.dispatch(email_enabled=True)

        self.assertEqual(result["skipped"], 1)
        mock_send.assert_called_once()

    def test_stale_sending_moves_to_review(self):
        self.dispatch()

        with database_connection(self.db_path) as connection:
            connection.execute("""
                UPDATE alert_notifications
                SET status = 'SENDING',
                    updated_at = datetime('now', '-20 minutes')
            """)

        recovered = recover_stale_notifications(
            db_path=self.db_path,
            stale_seconds=300,
        )

        self.assertEqual(recovered, 1)
        self.assertEqual(self.history()["status"], "REVIEW")

    @patch("app.alert_dispatcher.send_email_notification")
    def test_review_is_not_automatically_resent(self, mock_send):
        self.dispatch()

        with database_connection(self.db_path) as connection:
            connection.execute("""
                UPDATE alert_notifications
                SET status = 'REVIEW'
            """)

        result = self.dispatch(email_enabled=True)

        self.assertEqual(result["skipped"], 1)
        mock_send.assert_not_called()

    def test_recent_sending_not_recovered(self):
        self.dispatch()

        with database_connection(self.db_path) as connection:
            connection.execute("""
                UPDATE alert_notifications
                SET status = 'SENDING',
                    updated_at = CURRENT_TIMESTAMP
            """)

        recovered = recover_stale_notifications(
            db_path=self.db_path,
            stale_seconds=300,
        )

        self.assertEqual(recovered, 0)
        self.assertEqual(self.history()["status"], "SENDING")

    def test_summary_includes_review(self):
        self.dispatch()

        with database_connection(self.db_path) as connection:
            connection.execute("""
                UPDATE alert_notifications
                SET status = 'REVIEW'
            """)

        summary = get_notification_summary(
            db_path=self.db_path,
        )

        self.assertEqual(summary["review"], 1)
        self.assertEqual(summary["total"], 1)


if __name__ == "__main__":
    unittest.main()
