
"""Tests for Windows duplicate-alert suppression."""

import tempfile
import unittest

from datetime import datetime, timedelta
from pathlib import Path

from app.windows_ingest import ingest_windows_events

from database.db_manager import get_alert_count


class TestWindowsAlertSuppression(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "alerts.db"
        self.start = datetime(2026, 11, 10, 12, 0, 0)

    def make_event(self, seconds, ip="192.168.1.50"):
        return {
            "timestamp": (
                self.start + timedelta(seconds=seconds)
            ).isoformat(),
            "event_type": "FAILED_LOGIN",
            "ip_address": ip,
            "username": "admin",
            "event_origin": "windows_security",
            "is_remote_authentication": True,
            "windows_event_id": 4625,
            "windows_record_id": seconds + 1000,
        }

    def test_first_attack_creates_alert(self):
        events = [
            self.make_event(i * 10)
            for i in range(5)
        ]

        result = ingest_windows_events(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(
            result["detected_alerts"],
            1,
        )

        self.assertEqual(
            get_alert_count(self.db_path),
            1,
        )

    def test_repeated_batch_no_duplicate(self):
        events = [
            self.make_event(i * 10)
            for i in range(5)
        ]

        ingest_windows_events(
            events,
            db_path=self.db_path,
        )

        result = ingest_windows_events(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(
            result["saved_alerts"],
            0,
        )

        self.assertEqual(
            get_alert_count(self.db_path),
            1,
        )

    def test_old_attack_not_reported_with_unrelated_event(self):
        attack = [
            self.make_event(i * 10)
            for i in range(5)
        ]

        ingest_windows_events(
            attack,
            db_path=self.db_path,
        )

        result = ingest_windows_events(
            [
                self.make_event(
                    45,
                    ip="10.0.0.99",
                )
            ],
            db_path=self.db_path,
        )

        self.assertEqual(
            result["detected_alerts"],
            0,
        )

    def test_new_attack_from_another_ip(self):
        first_attack = [
            self.make_event(i * 10)
            for i in range(5)
        ]

        second_attack = [
            self.make_event(
                100 + i * 10,
                ip="10.0.0.99",
            )
            for i in range(5)
        ]

        ingest_windows_events(
            first_attack,
            db_path=self.db_path,
        )

        result = ingest_windows_events(
            second_attack,
            db_path=self.db_path,
        )

        self.assertEqual(
            result["detected_alerts"],
            1,
        )

        self.assertEqual(
            get_alert_count(self.db_path),
            2,
        )


if __name__ == "__main__":
    unittest.main()
