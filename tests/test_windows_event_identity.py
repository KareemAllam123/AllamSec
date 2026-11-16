
"""Windows event identity and replay protection tests."""

import tempfile
import unittest

from datetime import datetime, timedelta
from pathlib import Path

from app.windows_ingest import (
    get_event_hash,
    get_new_windows_events,
    ingest_windows_events,
)

from database.db_manager import (
    get_alert_count,
    get_event_count,
    initialize_database,
    save_events,
)


class TestWindowsEventIdentity(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.db_path = Path(self.temp.name) / "identity.db"

        initialize_database(self.db_path)

        self.start = datetime(
            2026, 11, 14, 12, 0, 0
        )

    def event(
        self,
        seconds,
        record_id,
        ip="192.168.1.50",
        username="admin",
        event_type="FAILED_LOGIN",
    ):
        return {
            "timestamp": (
                self.start + timedelta(seconds=seconds)
            ).isoformat(),
            "event_type": event_type,
            "ip_address": ip,
            "username": username,
            "event_origin": "windows_security",
            "is_remote_authentication": True,
            "windows_event_id": (
                4624 if event_type == "SUCCESS_LOGIN"
                else 4625
            ),
            "windows_record_id": record_id,
        }

    def test_hash_is_stable(self):
        event = self.event(0, 100)

        self.assertEqual(
            get_event_hash(event),
            get_event_hash(event.copy()),
        )

    def test_distinct_record_ids_have_distinct_hashes(self):
        first = self.event(0, 100)
        second = self.event(0, 101)

        self.assertNotEqual(
            get_event_hash(first),
            get_event_hash(second),
        )

    def test_new_events_identified(self):
        events = [
            self.event(0, 100),
            self.event(10, 101),
        ]

        result = get_new_windows_events(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(len(result), 2)

    def test_saved_events_not_new(self):
        event = self.event(0, 100)

        save_events(
            [event],
            "authentication",
            db_path=self.db_path,
        )

        result = get_new_windows_events(
            [event],
            db_path=self.db_path,
        )

        self.assertEqual(result, [])

    def test_duplicate_batch_entries(self):
        event = self.event(0, 100)

        result = get_new_windows_events(
            [event, event.copy()],
            db_path=self.db_path,
        )

        self.assertEqual(len(result), 1)

    def test_replayed_attack_not_reported(self):
        attack = [
            self.event(i * 10, 100 + i)
            for i in range(5)
        ]

        first = ingest_windows_events(
            attack,
            db_path=self.db_path,
        )

        second = ingest_windows_events(
            attack,
            db_path=self.db_path,
        )

        self.assertEqual(first["saved_alerts"], 1)
        self.assertEqual(second["saved_events"], 0)
        self.assertEqual(second["detected_alerts"], 0)
        self.assertEqual(get_event_count(self.db_path), 5)
        self.assertEqual(get_alert_count(self.db_path), 1)

    def test_cross_batch_attack(self):
        first_batch = [
            self.event(i * 10, 100 + i)
            for i in range(3)
        ]

        second_batch = [
            self.event(30, 103),
            self.event(40, 104),
        ]

        first = ingest_windows_events(
            first_batch,
            db_path=self.db_path,
        )

        second = ingest_windows_events(
            second_batch,
            db_path=self.db_path,
        )

        self.assertEqual(first["detected_alerts"], 0)
        self.assertEqual(second["detected_alerts"], 1)
        self.assertEqual(get_alert_count(self.db_path), 1)

    def test_same_timestamp_different_records(self):
        events = [
            self.event(0, 100 + i)
            for i in range(5)
        ]

        result = ingest_windows_events(
            events,
            db_path=self.db_path,
        )

        self.assertEqual(result["saved_events"], 5)
        self.assertEqual(result["detected_alerts"], 1)

    def test_unrelated_new_event_does_not_realert(self):
        attack = [
            self.event(i * 10, 100 + i)
            for i in range(5)
        ]

        ingest_windows_events(
            attack,
            db_path=self.db_path,
        )

        result = ingest_windows_events(
            [self.event(
                45,
                200,
                ip="10.0.0.99",
            )],
            db_path=self.db_path,
        )

        self.assertEqual(result["detected_alerts"], 0)


if __name__ == "__main__":
    unittest.main()
