import unittest
from datetime import datetime

from app.parser import parse_log_line


class TestLogParser(unittest.TestCase):
    """
    Unit tests for the AllamSec authentication log parser.

    These tests verify that valid authentication events are
    parsed correctly and malformed entries are rejected.
    """

    def test_valid_failed_login(self):
        """Verify that a valid failed login is parsed correctly."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "FAILED_LOGIN")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["ip_address"], "192.168.1.10")
        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 28, 10, 0, 1)
        )

    def test_valid_successful_login(self):
        """Verify that a successful login is parsed correctly."""

        line = (
            "2026-10-28 10:01:00 "
            "SUCCESS_LOGIN user=john ip=192.168.1.20"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["event_type"], "SUCCESS_LOGIN")
        self.assertEqual(event["username"], "john")
        self.assertEqual(event["ip_address"], "192.168.1.20")

    def test_invalid_ip_address(self):
        """Verify that invalid IP addresses are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=999.999.999.999"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_invalid_event_type(self):
        """Verify that unsupported event types are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "UNKNOWN_EVENT user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_invalid_timestamp(self):
        """Verify that invalid dates are rejected."""

        line = (
            "2026-99-99 10:00:01 "
            "FAILED_LOGIN user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_missing_username(self):
        """Verify that empty usernames are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user= ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_missing_ip_address(self):
        """Verify that empty IP addresses are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip="
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_incomplete_log_entry(self):
        """Verify that incomplete log entries are rejected."""

        line = "2026-10-28 FAILED_LOGIN user=admin"

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_empty_log_entry(self):
        """Verify that empty log entries are rejected."""

        line = ""

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_valid_ipv6_address(self):
        """Verify that valid IPv6 addresses are accepted."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=2001:db8::1"
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["ip_address"], "2001:db8::1")

    def test_invalid_time(self):
        """Verify that invalid times are rejected."""

        line = (
            "2026-10-28 25:99:99 "
            "FAILED_LOGIN user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_extra_log_fields(self):
        """Verify that entries with unexpected fields are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "FAILED_LOGIN user=admin ip=192.168.1.10 extra=data"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)

    def test_whitespace_handling(self):
        """Verify that extra whitespace does not break parsing."""

        line = (
            "  2026-10-28   10:00:01   "
            "FAILED_LOGIN   user=admin   ip=192.168.1.10  "
        )

        event = parse_log_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event["username"], "admin")

    def test_missing_event_type(self):
        """Verify that entries without an event type are rejected."""

        line = (
            "2026-10-28 10:00:01 "
            "user=admin ip=192.168.1.10"
        )

        event = parse_log_line(line)

        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()