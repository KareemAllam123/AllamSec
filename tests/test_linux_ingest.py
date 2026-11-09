
"""Integration tests for AllamSec Linux SSH ingestion."""

import tempfile
import unittest
from pathlib import Path

from app.linux_ingest import ingest_linux_file
from database.db_manager import get_connection


SAMPLE_LOGS = """\
Nov  8 10:00:01 ubuntu-server sshd[1201]: Failed password for invalid user admin from 192.168.1.50 port 52001 ssh2
Nov  8 10:00:08 ubuntu-server sshd[1202]: Failed password for invalid user admin from 192.168.1.50 port 52002 ssh2
Nov  8 10:00:15 ubuntu-server sshd[1203]: Failed password for invalid user admin from 192.168.1.50 port 52003 ssh2
Nov  8 10:00:22 ubuntu-server sshd[1204]: Failed password for invalid user admin from 192.168.1.50 port 52004 ssh2
Nov  8 10:00:29 ubuntu-server sshd[1205]: Failed password for invalid user admin from 192.168.1.50 port 52005 ssh2
Nov  8 10:02:01 ubuntu-server sshd[1210]: Accepted password for developer from 192.168.1.25 port 53001 ssh2
"""


class TestLinuxIngestion(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.folder = Path(self.temp_dir.name)
        self.db_path = self.folder / "test_allamsec.db"
        self.log_path = self.folder / "auth.log"

        self.log_path.write_text(
            SAMPLE_LOGS,
            encoding="utf-8",
        )

    def get_count(self, table):
        allowed_tables = {
            "security_events",
            "security_alerts",
        }

        if table not in allowed_tables:
            raise ValueError("Invalid table name")

        connection = get_connection(self.db_path)

        try:
            row = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()

            return row[0]
        finally:
            connection.close()

    def test_events_saved(self):
        result = ingest_linux_file(
            self.log_path,
            year=2026,
            db_path=self.db_path,
        )

        self.assertEqual(result["collected_events"], 6)
        self.assertEqual(result["saved_events"], 6)
        self.assertEqual(
            self.get_count("security_events"),
            6,
        )

    def test_login_counts(self):
        result = ingest_linux_file(
            self.log_path,
            year=2026,
            db_path=self.db_path,
        )

        self.assertEqual(result["failed_logins"], 5)
        self.assertEqual(result["successful_logins"], 1)
        self.assertEqual(result["invalid_lines"], 0)

    def test_duplicate_events_prevented(self):
        first = ingest_linux_file(
            self.log_path,
            year=2026,
            db_path=self.db_path,
        )

        second = ingest_linux_file(
            self.log_path,
            year=2026,
            db_path=self.db_path,
        )

        self.assertEqual(first["saved_events"], 6)
        self.assertEqual(second["saved_events"], 0)
        self.assertEqual(
            self.get_count("security_events"),
            6,
        )

    def test_brute_force_detection(self):
        result = ingest_linux_file(
            self.log_path,
            year=2026,
            db_path=self.db_path,
        )

        self.assertGreaterEqual(
            result["detected_alerts"],
            1,
        )

        self.assertGreaterEqual(
            result["saved_alerts"],
            1,
        )

        self.assertGreaterEqual(
            self.get_count("security_alerts"),
            1,
        )

    def test_duplicate_alerts_prevented(self):
        ingest_linux_file(
            self.log_path,
            year=2026,
            db_path=self.db_path,
        )

        original_count = self.get_count(
            "security_alerts"
        )

        second = ingest_linux_file(
            self.log_path,
            year=2026,
            db_path=self.db_path,
        )

        self.assertEqual(second["saved_alerts"], 0)
        self.assertEqual(
            self.get_count("security_alerts"),
            original_count,
        )

    def test_missing_log_file(self):
        missing = self.folder / "missing.log"

        with self.assertRaises(FileNotFoundError):
            ingest_linux_file(
                missing,
                year=2026,
                db_path=self.db_path,
            )


if __name__ == "__main__":
    unittest.main()
