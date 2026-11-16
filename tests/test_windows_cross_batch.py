
"""Tests for Windows cross-batch brute-force detection."""

import tempfile
import unittest

from datetime import datetime, timedelta
from pathlib import Path

from app.windows_ingest import ingest_windows_events

from database.db_manager import (
    get_alert_count,
    get_event_count,
)


class TestWindowsCrossBatch(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "test.db"

        self.start = datetime(
            2026, 11, 10, 12, 0, 0
        )

    def make_event(
        self,
        seconds,
        ip="192.168.1.50",
        username="admin",
        event_type="FAILED_LOGIN",
    ):
        return {
            "timestamp": (
                self.start
                + timedelta(seconds=seconds)
            ).isoformat(),
            "event_type": event_type,
            "ip_address": ip,
            "username": username,
            "event_origin": "windows_security",
            "is_remote_authentication": True,
            "windows_event_id": (
                4625 if event_type == "FAILED_LOGIN"
                else 4624
            ),
            "windows_record_id": seconds + 1000,
        }

    def test_attack_across_two_batches(self):
        first_batch = [
            self.make_event(0),
            self.make_event(10),
            self.make_event(20),
        ]

        second_batch = [
            self.make_event(30),
            self.make_event(40),
        ]

        first = ingest_windows_events(
            first_batch,
            db_path=self.db_path,
        )

        self.assertEqual(
            first["detected_alerts"],
            0,
        )

        second = ingest_windows_events(
            second_batch,
            db_path=self.db_path,
        )

        self.assertGreaterEqual(
            second["detected_alerts"],
            1,
        )

        self.assertGreaterEqual(
            get_alert_count(self.db_path),
            1,
        )

    def test_events_persist_across_batches(self):
        ingest_windows_events(
            [self.make_event(0)],
            db_path=self.db_path,
        )

        ingest_windows_events(
            [self.make_event(10)],
            db_path=self.db_path,
        )

        self.assertEqual(
            get_event_count(self.db_path),
            2,
        )

    def test_no_alert_below_threshold(self):
        ingest_windows_events(
            [
                self.make_event(0),
                self.make_event(10),
            ],
            db_path=self.db_path,
        )

        result = ingest_windows_events(
            [
                self.make_event(20),
                self.make_event(30),
            ],
            db_path=self.db_path,
        )

        self.assertEqual(
            result["detected_alerts"],
            0,
        )

    def test_events_outside_window(self):
        ingest_windows_events(
            [
                self.make_event(0),
                self.make_event(10),
                self.make_event(20),
            ],
            db_path=self.db_path,
        )

        result = ingest_windows_events(
            [
                self.make_event(200),
                self.make_event(210),
            ],
            db_path=self.db_path,
        )

        self.assertEqual(
            result["detected_alerts"],
            0,
        )

    def test_different_attackers(self):
        ingest_windows_events(
            [
                self.make_event(0),
                self.make_event(10),
                self.make_event(20),
            ],
            db_path=self.db_path,
        )

        result = ingest_windows_events(
            [
                self.make_event(
                    30,
                    ip="10.0.0.20",
                ),
                self.make_event(
                    40,
                    ip="10.0.0.20",
                ),
            ],
            db_path=self.db_path,
        )

        self.assertEqual(
            result["detected_alerts"],
            0,
        )

    def test_repeated_ingestion_does_not_duplicate_events(self):
        events = [
            self.make_event(0),
            self.make_event(10),
        ]

        ingest_windows_events(
            events,
            db_path=self.db_path,
        )

        ingest_windows_events(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(
            get_event_count(self.db_path),
            2,
        )


if __name__ == "__main__":
    unittest.main()
