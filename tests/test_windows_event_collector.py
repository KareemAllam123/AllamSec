
"""Tests for Phase 9 Windows Security event collection."""

import unittest

from app.windows_event_collector import (
    parse_windows_event,
    parse_windows_xml,
)


def sample_event(
    event_id=4625,
    username="testuser",
    ip="192.0.2.10",
    logon_type=3,
):
    return f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <EventID>{event_id}</EventID>
            <EventRecordID>12345</EventRecordID>
            <Computer>TEST-PC</Computer>
            <TimeCreated SystemTime="2026-11-07T12:00:00.000Z"/>
        </System>
        <EventData>
            <Data Name="TargetUserName">{username}</Data>
            <Data Name="IpAddress">{ip}</Data>
            <Data Name="LogonType">{logon_type}</Data>
        </EventData>
    </Event>
    """


class TestWindowsEventCollector(unittest.TestCase):

    def test_failed_login(self):
        event = parse_windows_event(sample_event())
        self.assertEqual(event["event_type"], "FAILED_LOGIN")

    def test_successful_login(self):
        event = parse_windows_event(
            sample_event(event_id=4624)
        )
        self.assertEqual(event["event_type"], "SUCCESS_LOGIN")

    def test_local_logon_collected(self):
        event = parse_windows_event(
            sample_event(logon_type=2, ip="127.0.0.1")
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["logon_type_name"], "INTERACTIVE")
        self.assertFalse(event["is_remote_authentication"])

    def test_service_logon_collected(self):
        event = parse_windows_event(
            sample_event(logon_type=5, ip="-")
        )
        self.assertIsNotNone(event)
        self.assertEqual(event["logon_type_name"], "SERVICE")
        self.assertFalse(event["is_remote_authentication"])

    def test_remote_logon_identified(self):
        event = parse_windows_event(
            sample_event(logon_type=3)
        )
        self.assertTrue(event["is_remote_authentication"])

    def test_loopback_not_remote(self):
        event = parse_windows_event(
            sample_event(logon_type=3, ip="127.0.0.1")
        )
        self.assertFalse(event["is_remote_authentication"])

    def test_unrelated_event_excluded(self):
        event = parse_windows_event(
            sample_event(event_id=4634)
        )
        self.assertIsNone(event)

    def test_multiple_events(self):
        events, invalid = parse_windows_xml(
            sample_event() + sample_event(event_id=4624)
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(invalid, 0)

    def test_malformed_event(self):
        events, invalid = parse_windows_xml(
            "<Event><broken></Event>"
        )
        self.assertEqual(events, [])
        self.assertEqual(invalid, 1)

    def test_windows_metadata(self):
        event = parse_windows_event(sample_event())
        self.assertEqual(event["windows_event_id"], 4625)
        self.assertEqual(event["windows_record_id"], "12345")
        self.assertEqual(event["computer"], "TEST-PC")


if __name__ == "__main__":
    unittest.main()
