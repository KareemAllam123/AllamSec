"""Automated tests for the AllamSec Flask dashboard."""

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from dashboard.web_app import create_app
from database.db_manager import save_alerts, save_events


class TestDashboard(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.db_path = (
            Path(self.temp_dir.name) / "dashboard_test.db"
        )

        self.app = create_app(db_path=self.db_path)
        self.app.config["TESTING"] = True

        self.client = self.app.test_client()

        self.event = {
            "timestamp": datetime(2026, 10, 28, 10, 0, 1),
            "event_type": "FAILED_LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.10",
        }

        self.alert = {
            "alert_type": "POSSIBLE_BRUTE_FORCE",
            "severity": "HIGH",
            "risk_score": 65,
            "source_ip": "192.168.1.10",
            "target_account": "admin",
            "failed_attempts": 5,
            "first_attempt": datetime(2026, 10, 28, 10, 0, 1),
            "last_attempt": datetime(2026, 10, 28, 10, 0, 9),
            "description": "Multiple failed login attempts.",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def add_sample_data(self):
        save_events(
            [self.event],
            "authentication",
            self.db_path,
        )

        save_alerts(
            [self.alert],
            self.db_path,
        )

    def test_homepage_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Overview", response.data)

    def test_alerts_page_loads(self):
        response = self.client.get("/alerts")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Alerts", response.data)

    def test_events_page_loads(self):
        response = self.client.get("/events")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Events", response.data)

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["status"],
            "online",
        )

    def test_stats_api_empty_database(self):
        response = self.client.get("/api/stats")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["total_events"],
            0,
        )
        self.assertEqual(
            response.json["total_alerts"],
            0,
        )

    def test_stats_api_with_data(self):
        self.add_sample_data()

        response = self.client.get("/api/stats")

        self.assertEqual(
            response.json["total_events"],
            1,
        )
        self.assertEqual(
            response.json["total_alerts"],
            1,
        )
        self.assertEqual(
            response.json["highest_risk_score"],
            65,
        )

    def test_alerts_api(self):
        self.add_sample_data()

        response = self.client.get("/api/alerts")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json), 1)

        self.assertEqual(
            response.json[0]["alert_type"],
            "POSSIBLE_BRUTE_FORCE",
        )

    def test_alert_detail_page(self):
        self.add_sample_data()

        response = self.client.get("/alerts/1")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Multiple failed login attempts.",
            response.data,
        )

    def test_missing_alert_returns_404(self):
        response = self.client.get("/alerts/999")

        self.assertEqual(response.status_code, 404)

    def test_severity_filter(self):
        self.add_sample_data()

        high = self.client.get(
            "/alerts?severity=HIGH"
        )

        critical = self.client.get(
            "/alerts?severity=CRITICAL"
        )

        self.assertEqual(high.status_code, 200)
        self.assertEqual(critical.status_code, 200)

        self.assertIn(
            b"POSSIBLE BRUTE FORCE",
            high.data,
        )

        self.assertNotIn(
            b"POSSIBLE BRUTE FORCE",
            critical.data,
        )

    def test_invalid_severity_filter(self):
        response = self.client.get(
            "/alerts?severity=INVALID"
        )

        self.assertEqual(response.status_code, 400)

    def test_event_source_filter(self):
        self.add_sample_data()

        response = self.client.get(
            "/events?source=authentication"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"FAILED_LOGIN", response.data)

    def test_invalid_event_source(self):
        response = self.client.get(
            "/events?source=unknown"
        )

        self.assertEqual(response.status_code, 400)

    def test_dashboard_displays_stored_alerts(self):
        self.add_sample_data()

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"POSSIBLE BRUTE FORCE",
            response.data,
        )

    def test_css_file_loads(self):
        response = self.client.get(
            "/static/css/style.css"
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"--background", response.data)


if __name__ == "__main__":
    unittest.main()