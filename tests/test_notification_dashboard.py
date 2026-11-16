
"""Tests for AllamSec notification dashboard."""

import tempfile
import unittest
from pathlib import Path

from app.alert_dispatcher import dispatch_alerts
from dashboard.web_app import create_app
from database.db_manager import initialize_database, save_alerts


class TestNotificationDashboard(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "dashboard.db"

        initialize_database(self.db_path)

        self.app = create_app(db_path=self.db_path)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_notifications_page_loads(self):
        response = self.client.get("/notifications")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Notification Center", response.data)

    def test_notifications_api_empty(self):
        response = self.client.get("/api/notifications")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["summary"]["total"], 0)
        self.assertEqual(data["notifications"], [])

    def test_notification_visible_in_dashboard(self):
        alert = {
            "alert_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "risk_score": 85,
            "source_ip": "192.168.1.50",
            "username": "admin",
            "description": "Repeated login failures",
            "first_attempt": "2026-11-09T10:00:00",
            "last_attempt": "2026-11-09T10:01:00",
        }

        save_alerts([alert], db_path=self.db_path)

        dispatch_alerts(
            [alert],
            db_path=self.db_path,
            email_enabled=False,
        )

        response = self.client.get("/notifications")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"BRUTE_FORCE", response.data)
        self.assertIn(b"192.168.1.50", response.data)

        api_response = self.client.get("/api/notifications")
        data = api_response.get_json()

        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(len(data["notifications"]), 1)


if __name__ == "__main__":
    unittest.main()
