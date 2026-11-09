
"""Tests for AllamSec Linux SSH authentication collection."""

import tempfile
import unittest
from pathlib import Path

from app.linux_event_collector import (
    parse_linux_auth_line,
    read_linux_auth_file,
)


class TestLinuxEventCollector(unittest.TestCase):

    def test_failed_password(self):
        line = (
            "Nov  8 10:00:01 ubuntu sshd[123]: "
            "Failed password for root from "
            "192.168.1.50 port 52001 ssh2"
        )

        event = parse_linux_auth_line(line, year=2026)

        self.assertIsNotNone(event)
        self.assertEqual(
            event["event_type"],
            "FAILED_LOGIN",
        )
        self.assertEqual(event["username"], "root")
        self.assertEqual(
            event["ip_address"],
            "192.168.1.50",
        )

    def test_invalid_username(self):
        line = (
            "Nov  8 10:00:01 ubuntu sshd[123]: "
            "Failed password for invalid user admin "
            "from 192.168.1.50 port 52001 ssh2"
        )

        event = parse_linux_auth_line(line, year=2026)

        self.assertTrue(event["invalid_user"])
        self.assertEqual(event["username"], "admin")

    def test_successful_password(self):
        line = (
            "Nov  8 10:02:01 ubuntu sshd[123]: "
            "Accepted password for kareem "
            "from 192.168.1.25 port 53001 ssh2"
        )

        event = parse_linux_auth_line(line, year=2026)

        self.assertEqual(
            event["event_type"],
            "SUCCESS_LOGIN",
        )

    def test_successful_publickey(self):
        line = (
            "Nov  8 10:02:01 ubuntu sshd[123]: "
            "Accepted publickey for developer "
            "from 192.168.1.30 port 53002 ssh2"
        )

        event = parse_linux_auth_line(line, year=2026)

        self.assertEqual(
            event["authentication_method"],
            "publickey",
        )

    def test_ignores_unrelated_lines(self):
        line = (
            "Nov  8 10:00:01 ubuntu CRON[123]: "
            "Scheduled task executed"
        )

        self.assertIsNone(
            parse_linux_auth_line(line, year=2026)
        )

    def test_malformed_timestamp(self):
        line = (
            "Nov 99 10:00:01 ubuntu sshd[123]: "
            "Failed password for root from "
            "192.168.1.50 port 52001 ssh2"
        )

        self.assertIsNone(
            parse_linux_auth_line(line, year=2026)
        )

    def test_file_collection(self):
        content = (
            "Nov  8 10:00:01 ubuntu sshd[123]: "
            "Failed password for root from "
            "192.168.1.50 port 52001 ssh2\n"
            "Nov  8 10:00:02 ubuntu CRON[124]: "
            "Scheduled task executed\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(content, encoding="utf-8")

            events, invalid = read_linux_auth_file(
                path,
                year=2026,
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(invalid, 0)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.log"

            with self.assertRaises(FileNotFoundError):
                read_linux_auth_file(path, year=2026)


if __name__ == "__main__":
    unittest.main()
