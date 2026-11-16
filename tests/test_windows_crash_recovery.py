
"""Tests for Windows detection recovery after interruption."""

import tempfile
import unittest

from datetime import datetime, timedelta
from pathlib import Path

from app.windows_ingest import (
    ingest_windows_events,
    recover_windows_detection,
)

from database.db_manager import (
    database_connection,
    initialize_database,
    save_events,
)


class TestWindowsCrashRecovery(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "recovery.db"

        initialize_database(self.db_path)

        self.start = datetime(2026, 11, 14, 12, 0, 0)

    def event(self, index):
        return {
            "timestamp": (
                self.start + timedelta(seconds=index * 10)
            ).isoformat(),
            "event_type": "FAILED_LOGIN",
            "ip_address": "192.168.1.50",
            "username": "admin",
            "event_origin": "windows_security",
            "is_remote_authentication": True,
            "windows_event_id": 4625,
            "windows_record_id": 100 + index,
        }

    def alert_count(self):
        with database_connection(self.db_path) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM security_alerts"
            ).fetchone()[0]

    def test_empty_recovery(self):
        result = recover_windows_detection(
            [],
            db_path=self.db_path,
        )

        self.assertEqual(result["recovered_alerts"], 0)

    def test_recovery_after_events_saved(self):
        events = [self.event(i) for i in range(5)]

        # Simulate a crash after event storage
        # but before detection and alert storage.
        save_events(
            events,
            "authentication",
            db_path=self.db_path,
        )

        self.assertEqual(self.alert_count(), 0)

        result = recover_windows_detection(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(result["recovered_alerts"], 1)
        self.assertEqual(self.alert_count(), 1)

    def test_recovery_is_idempotent(self):
        events = [self.event(i) for i in range(5)]

        save_events(
            events,
            "authentication",
            db_path=self.db_path,
        )

        first = recover_windows_detection(
            events,
            db_path=self.db_path,
        )

        second = recover_windows_detection(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(first["recovered_alerts"], 1)
        self.assertEqual(second["recovered_alerts"], 0)
        self.assertEqual(self.alert_count(), 1)

    def test_no_attack_below_threshold(self):
        events = [self.event(i) for i in range(3)]

        save_events(
            events,
            "authentication",
            db_path=self.db_path,
        )

        result = recover_windows_detection(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(result["recovered_alerts"], 0)

    def test_existing_alert_not_duplicated(self):
        events = [self.event(i) for i in range(5)]

        ingest_windows_events(
            events,
            db_path=self.db_path,
        )

        result = recover_windows_detection(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(result["recovered_alerts"], 0)
        self.assertEqual(self.alert_count(), 1)


if __name__ == "__main__":
    unittest.main()
