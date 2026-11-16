
"""Tests for indexed Windows event history retrieval."""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from app.windows_ingest import (
    get_windows_event_history,
    ingest_windows_events,
)


class TestWindowsHistory(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "history.db"
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

    def test_history_within_window(self):
        ingest_windows_events(
            [
                self.make_event(0),
                self.make_event(30),
                self.make_event(120),
            ],
            db_path=self.db_path,
        )

        history = get_windows_event_history(
            self.start,
            self.start + timedelta(seconds=60),
            db_path=self.db_path,
        )

        self.assertEqual(len(history), 2)

    def test_history_excludes_older_events(self):
        ingest_windows_events(
            [
                self.make_event(0),
                self.make_event(120),
            ],
            db_path=self.db_path,
        )

        history = get_windows_event_history(
            self.start + timedelta(seconds=60),
            self.start + timedelta(seconds=180),
            db_path=self.db_path,
        )

        self.assertEqual(len(history), 1)

    def test_empty_history(self):
        ingest_windows_events(
            [self.make_event(0)],
            db_path=self.db_path,
        )

        history = get_windows_event_history(
            self.start + timedelta(days=1),
            self.start + timedelta(days=2),
            db_path=self.db_path,
        )

        self.assertEqual(history, [])


if __name__ == "__main__":
    unittest.main()
