import sqlite3
import tempfile
import unittest

from datetime import datetime
from pathlib import Path

from database.db_manager import (
    create_hash,
    initialize_database,
    save_events,
    save_alerts,
    get_event_count,
    get_alert_count,
    get_recent_alerts,
    get_database_summary,
)


class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.db_path = (
            Path(self.temp_dir.name) / "test_allamsec.db"
        )

        initialize_database(self.db_path)

        self.auth_event = {
            "timestamp": datetime(2026, 10, 28, 10, 0, 1),
            "event_type": "FAILED_LOGIN",
            "username": "admin",
            "ip_address": "192.168.1.10",
        }

        self.network_event = {
            "timestamp": datetime(2026, 10, 28, 13, 0, 1),
            "status": "BLOCKED",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.50",
            "destination_port": 22,
        }

        self.alert = {
            "alert_type": "POSSIBLE_BRUTE_FORCE",
            "severity": "HIGH",
            "risk_score": 65,
            "source_ip": "192.168.1.10",
            "username": "admin",
            "failed_attempts": 5,
            "first_attempt": datetime(2026, 10, 28, 10, 0, 1),
            "last_attempt": datetime(2026, 10, 28, 10, 0, 9),
            "description": "Multiple failed login attempts.",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_database_created(self):
        self.assertTrue(self.db_path.exists())

    def test_tables_created(self):
        connection = sqlite3.connect(self.db_path)

        try:
            rows = connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table'"
            ).fetchall()
        finally:
            connection.close()

        names = {row[0] for row in rows}

        self.assertIn("security_events", names)
        self.assertIn("security_alerts", names)

    def test_initialization_is_repeatable(self):
        initialize_database(self.db_path)

        self.assertTrue(self.db_path.exists())

    def test_save_authentication_event(self):
        saved = save_events(
            [self.auth_event],
            "authentication",
            self.db_path,
        )

        self.assertEqual(saved, 1)
        self.assertEqual(get_event_count(self.db_path), 1)

    def test_save_network_event(self):
        saved = save_events(
            [self.network_event],
            "network",
            self.db_path,
        )

        self.assertEqual(saved, 1)
        self.assertEqual(get_event_count(self.db_path), 1)

    def test_save_multiple_event_types(self):
        save_events(
            [self.auth_event],
            "authentication",
            self.db_path,
        )

        save_events(
            [self.network_event],
            "network",
            self.db_path,
        )

        self.assertEqual(get_event_count(self.db_path), 2)

    def test_duplicate_event_prevention(self):
        first = save_events(
            [self.auth_event],
            "authentication",
            self.db_path,
        )

        second = save_events(
            [self.auth_event],
            "authentication",
            self.db_path,
        )

        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(get_event_count(self.db_path), 1)

    def test_invalid_event_source(self):
        with self.assertRaises(ValueError):
            save_events(
                [self.auth_event],
                "unknown",
                self.db_path,
            )

    def test_save_security_alert(self):
        saved = save_alerts(
            [self.alert],
            self.db_path,
        )

        self.assertEqual(saved, 1)
        self.assertEqual(get_alert_count(self.db_path), 1)

    def test_duplicate_alert_prevention(self):
        first = save_alerts(
            [self.alert],
            self.db_path,
        )

        second = save_alerts(
            [self.alert],
            self.db_path,
        )

        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(get_alert_count(self.db_path), 1)

    def test_existing_alert_risk_updates(self):
        save_alerts(
            [self.alert],
            self.db_path,
        )

        updated = self.alert.copy()
        updated["risk_score"] = 85
        updated["severity"] = "CRITICAL"

        saved = save_alerts(
            [updated],
            self.db_path,
        )

        self.assertEqual(saved, 0)
        self.assertEqual(get_alert_count(self.db_path), 1)

        alerts = get_recent_alerts(
            db_path=self.db_path,
        )

        self.assertEqual(alerts[0]["risk_score"], 85)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_alerts_persist_between_connections(self):
        save_alerts(
            [self.alert],
            self.db_path,
        )

        connection = sqlite3.connect(self.db_path)

        try:
            count = connection.execute(
                "SELECT COUNT(*) FROM security_alerts"
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(count, 1)

    def test_get_recent_alerts(self):
        save_alerts(
            [self.alert],
            self.db_path,
        )

        alerts = get_recent_alerts(
            db_path=self.db_path,
        )

        self.assertEqual(len(alerts), 1)

        self.assertEqual(
            alerts[0]["alert_type"],
            "POSSIBLE_BRUTE_FORCE",
        )

    def test_alerts_ordered_by_risk(self):
        save_alerts(
            [self.alert],
            self.db_path,
        )

        critical = self.alert.copy()
        critical["alert_type"] = "POSSIBLE_ACCOUNT_COMPROMISE"
        critical["risk_score"] = 95
        critical["severity"] = "CRITICAL"

        save_alerts(
            [critical],
            self.db_path,
        )

        alerts = get_recent_alerts(
            db_path=self.db_path,
        )

        self.assertEqual(
            [alert["risk_score"] for alert in alerts],
            [95, 65],
        )

    def test_database_summary(self):
        save_events(
            [self.auth_event],
            "authentication",
            self.db_path,
        )

        save_events(
            [self.network_event],
            "network",
            self.db_path,
        )

        save_alerts(
            [self.alert],
            self.db_path,
        )

        summary = get_database_summary(self.db_path)

        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["total_alerts"], 1)
        self.assertEqual(summary["critical_alerts"], 0)
        self.assertEqual(summary["highest_risk_score"], 65)

    def test_empty_database_summary(self):
        summary = get_database_summary(self.db_path)

        self.assertEqual(summary["total_events"], 0)
        self.assertEqual(summary["total_alerts"], 0)
        self.assertIsNone(summary["highest_risk_score"])

    def test_invalid_alert_limit(self):
        with self.assertRaises(ValueError):
            get_recent_alerts(
                limit=0,
                db_path=self.db_path,
            )

    def test_hash_is_consistent(self):
        first = create_hash({
            "username": "admin",
            "ip": "192.168.1.10",
        })

        second = create_hash({
            "ip": "192.168.1.10",
            "username": "admin",
        })

        self.assertEqual(first, second)

    def test_different_records_have_different_hashes(self):
        first = create_hash({"port": 22})
        second = create_hash({"port": 443})

        self.assertNotEqual(first, second)

    def test_no_duplicate_alerts_in_same_batch(self):
        saved = save_alerts(
            [self.alert, self.alert],
            self.db_path,
        )

        self.assertEqual(saved, 1)
        self.assertEqual(get_alert_count(self.db_path), 1)


if __name__ == "__main__":
    unittest.main()