"""Tests for AllamSec Phase 8."""

import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from dashboard.web_app import create_app
from database.db_manager import (
    get_alert_management_summary,
    get_threat_analytics,
    initialize_alert_management,
    save_alerts,
    save_events,
    update_alert_investigation,
)


class TestPhase8(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = (
            Path(self.temp_dir.name) / "phase8_test.db"
        )

        self.app = create_app(db_path=self.db_path)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.alert = {
            "alert_type": "POSSIBLE_BRUTE_FORCE",
            "severity": "HIGH",
            "risk_score": 65,
            "source_ip": "192.168.1.10",
            "target_account": "admin",
            "failed_attempts": 5,
            "first_attempt": datetime(2026, 10, 28, 10, 0),
            "last_attempt": datetime(2026, 10, 28, 10, 1),
            "description": "Multiple failed logins.",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def add_alert(self):
        save_alerts([self.alert], self.db_path)

    def test_analytics_page(self):
        response = self.client.get("/analytics")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Threat Analytics", response.data)

    def test_analytics_api(self):
        response = self.client.get("/api/analytics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("severity", response.json)
        self.assertIn("attack_types", response.json)
        self.assertIn("event_activity", response.json)

    def test_analytics_severity_counts(self):
        self.add_alert()
        data = get_threat_analytics(self.db_path)
        self.assertEqual(data["severity"]["HIGH"], 1)
        self.assertEqual(data["severity"]["CRITICAL"], 0)

    def test_analytics_attack_types(self):
        self.add_alert()
        data = get_threat_analytics(self.db_path)
        self.assertEqual(
            data["attack_types"][0]["alert_type"],
            "POSSIBLE_BRUTE_FORCE",
        )

    def test_default_alert_status(self):
        self.add_alert()
        summary = get_alert_management_summary(
            self.db_path
        )
        self.assertEqual(summary["OPEN"], 1)

    def test_update_investigation(self):
        self.add_alert()
        updated = update_alert_investigation(
            1,
            "INVESTIGATING",
            "Reviewing authentication logs.",
            self.db_path,
        )
        self.assertTrue(updated)

        summary = get_alert_management_summary(
            self.db_path
        )
        self.assertEqual(summary["INVESTIGATING"], 1)
        self.assertEqual(summary["OPEN"], 0)

    def test_resolve_alert(self):
        self.add_alert()
        update_alert_investigation(
            1, "RESOLVED", "Reviewed.", self.db_path
        )
        summary = get_alert_management_summary(
            self.db_path
        )
        self.assertEqual(summary["RESOLVED"], 1)

    def test_invalid_status(self):
        self.add_alert()
        with self.assertRaises(ValueError):
            update_alert_investigation(
                1, "DELETED", "", self.db_path
            )

    def test_missing_alert(self):
        updated = update_alert_investigation(
            999, "RESOLVED", "", self.db_path
        )
        self.assertFalse(updated)

    def test_investigation_form(self):
        self.add_alert()
        response = self.client.get("/alerts/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Save Investigation", response.data)

    def test_investigation_post(self):
        self.add_alert()
        response = self.client.post(
            "/alerts/1/update",
            data={
                "status": "INVESTIGATING",
                "notes": "Checking failed logins.",
            },
        )
        self.assertEqual(response.status_code, 302)

        summary = get_alert_management_summary(
            self.db_path
        )
        self.assertEqual(summary["INVESTIGATING"], 1)

    def test_invalid_status_post(self):
        self.add_alert()
        response = self.client.post(
            "/alerts/1/update",
            data={"status": "INVALID", "notes": ""},
        )
        self.assertEqual(response.status_code, 400)

    def test_status_filter(self):
        self.add_alert()
        response = self.client.get(
            "/alerts?status=OPEN"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"POSSIBLE BRUTE FORCE", response.data)

    def test_search_filter(self):
        self.add_alert()
        response = self.client.get(
            "/alerts?search=192.168.1.10"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"POSSIBLE BRUTE FORCE", response.data)

    def test_search_no_results(self):
        self.add_alert()
        response = self.client.get(
            "/alerts?search=10.255.255.255"
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(
            b"POSSIBLE BRUTE FORCE", response.data
        )

    def test_migration_repeatable(self):
        initialize_alert_management(self.db_path)
        initialize_alert_management(self.db_path)
        self.assertEqual(
            get_alert_management_summary(
                self.db_path
            )["OPEN"],
            0,
        )

    def test_event_activity(self):
        event = {
            "timestamp": datetime(2026, 10, 28, 10, 0),
            "event_type": "FAILED_LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.10",
        }

        save_events(
            [event], "authentication", self.db_path
        )

        data = get_threat_analytics(self.db_path)

        self.assertEqual(
            data["event_activity"][0]["day"],
            "2026-10-28",
        )
        self.assertEqual(
            data["event_activity"][0]["total"],
            1,
        )


if __name__ == "__main__":
    unittest.main()