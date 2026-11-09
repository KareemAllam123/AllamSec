
"""Tests for AllamSec Windows checkpoint persistence."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.windows_checkpoint import (
    clear_checkpoint,
    load_checkpoint,
    save_checkpoint,
)
from app.windows_monitor import process_windows_batch


class TestWindowsCheckpoint(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.checkpoint_path = (
            Path(self.temp_dir.name) / "checkpoint.json"
        )

    def test_missing_checkpoint(self):
        self.assertIsNone(
            load_checkpoint(self.checkpoint_path)
        )

    def test_save_and_load(self):
        save_checkpoint(12345, self.checkpoint_path)

        self.assertEqual(
            load_checkpoint(self.checkpoint_path),
            12345,
        )

    def test_checkpoint_update(self):
        save_checkpoint(100, self.checkpoint_path)
        save_checkpoint(200, self.checkpoint_path)

        self.assertEqual(
            load_checkpoint(self.checkpoint_path),
            200,
        )

    def test_checkpoint_survives_reload(self):
        save_checkpoint(500, self.checkpoint_path)

        self.assertEqual(
            load_checkpoint(self.checkpoint_path),
            500,
        )

    def test_clear_checkpoint(self):
        save_checkpoint(100, self.checkpoint_path)
        clear_checkpoint(self.checkpoint_path)

        self.assertIsNone(
            load_checkpoint(self.checkpoint_path)
        )

    def test_invalid_checkpoint(self):
        with self.assertRaises(ValueError):
            save_checkpoint(-1, self.checkpoint_path)

    def test_corrupt_checkpoint(self):
        self.checkpoint_path.write_text(
            "{invalid json",
            encoding="utf-8",
        )

        with self.assertRaises(RuntimeError):
            load_checkpoint(self.checkpoint_path)

    def test_checkpoint_after_successful_ingestion(self):
        events = [
            {
                "timestamp": "2026-11-08T10:00:00",
                "event_type": "SUCCESS_LOGIN",
                "windows_record_id": "100",
            }
        ]

        result = {
            "collected_events": 1,
            "saved_events": 1,
            "remote_events": 0,
            "saved_alerts": 0,
        }

        with (
            patch(
                "app.windows_monitor.collect_windows_events_since",
                return_value=(events, 0),
            ),
            patch(
                "app.windows_monitor.ingest_windows_events",
                return_value=result,
            ),
        ):
            output = process_windows_batch(
                checkpoint_path=self.checkpoint_path,
                max_events=10,
            )

        self.assertEqual(output["checkpoint"], 100)
        self.assertEqual(
            load_checkpoint(self.checkpoint_path),
            100,
        )

    def test_failed_ingestion_preserves_checkpoint(self):
        save_checkpoint(50, self.checkpoint_path)

        events = [
            {"windows_record_id": "51"}
        ]

        with (
            patch(
                "app.windows_monitor.collect_windows_events_since",
                return_value=(events, 0),
            ),
            patch(
                "app.windows_monitor.ingest_windows_events",
                side_effect=RuntimeError("Database unavailable"),
            ),
        ):
            with self.assertRaises(RuntimeError):
                process_windows_batch(
                    checkpoint_path=self.checkpoint_path,
                    max_events=10,
                )

        self.assertEqual(
            load_checkpoint(self.checkpoint_path),
            50,
        )

    def test_multiple_batches(self):
        batches = [
            (
                [
                    {"windows_record_id": "101"},
                    {"windows_record_id": "102"},
                ],
                0,
            ),
            (
                [
                    {"windows_record_id": "103"},
                ],
                0,
            ),
        ]

        result = {
            "collected_events": 2,
            "saved_events": 2,
            "remote_events": 0,
            "saved_alerts": 0,
        }

        with (
            patch(
                "app.windows_monitor.collect_windows_events_since",
                side_effect=batches,
            ),
            patch(
                "app.windows_monitor.ingest_windows_events",
                return_value=result,
            ),
        ):
            output = process_windows_batch(
                checkpoint_path=self.checkpoint_path,
                max_events=2,
            )

        self.assertEqual(output["batches"], 2)
        self.assertEqual(output["checkpoint"], 103)


if __name__ == "__main__":
    unittest.main()
