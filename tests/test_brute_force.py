import unittest
from datetime import datetime, timedelta

from detection.brute_force import detect_brute_force


class TestBruteForceDetection(unittest.TestCase):
    """
    Unit tests for the AllamSec brute-force detection engine.

    These tests verify that AllamSec correctly identifies
    suspicious authentication activity.
    """

    def setUp(self):
        """Set up a starting timestamp for each test."""

        self.start_time = datetime(2026, 10, 28, 10, 0, 0)

    def create_event(
        self,
        timestamp,
        ip_address="192.168.1.10",
        username="admin",
        event_type="FAILED_LOGIN"
    ):
        """Create a simulated authentication event."""

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "ip_address": ip_address,
            "username": username
        }

    def create_failed_attempts(
        self,
        count=5,
        interval_seconds=2,
        ip_address="192.168.1.10",
        username="admin"
    ):
        """Generate multiple failed login attempts."""

        events = []

        for i in range(count):

            timestamp = self.start_time + timedelta(
                seconds=i * interval_seconds
            )

            events.append(
                self.create_event(
                    timestamp=timestamp,
                    ip_address=ip_address,
                    username=username
                )
            )

        return events

    # --------------------------------------------------
    # Test 1: Detect brute-force attacks
    # --------------------------------------------------

    def test_detects_brute_force_attack(self):
        """Detect five failed logins within 60 seconds."""

        events = self.create_failed_attempts(count=5)

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "POSSIBLE_BRUTE_FORCE"
        )
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["failed_attempts"], 5)
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.10")
        self.assertEqual(alerts[0]["target_account"], "admin")

    # --------------------------------------------------
    # Test 2: Ignore attempts below the threshold
    # --------------------------------------------------

    def test_no_alert_below_threshold(self):
        """Do not alert when fewer than five failures occur."""

        events = self.create_failed_attempts(count=4)

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    # --------------------------------------------------
    # Test 3: Respect the detection time window
    # --------------------------------------------------

    def test_no_alert_outside_time_window(self):
        """Do not alert when failures are too far apart."""

        events = self.create_failed_attempts(
            count=5,
            interval_seconds=20
        )

        alerts = detect_brute_force(
            events,
            threshold=5,
            window_seconds=60
        )

        self.assertEqual(len(alerts), 0)

    # --------------------------------------------------
    # Test 4: Detect attacks from separate IP addresses
    # --------------------------------------------------

    def test_detects_multiple_attackers(self):
        """Detect independent brute-force attacks."""

        events = self.create_failed_attempts(
            count=5,
            ip_address="192.168.1.10"
        )

        events += self.create_failed_attempts(
            count=5,
            ip_address="192.168.1.50"
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 2)

        detected_ips = {
            alert["source_ip"]
            for alert in alerts
        }

        self.assertEqual(
            detected_ips,
            {"192.168.1.10", "192.168.1.50"}
        )

    # --------------------------------------------------
    # Test 5: Detect possible account compromise
    # --------------------------------------------------

    def test_detects_possible_account_compromise(self):
        """
        Detect a successful login shortly after
        repeated failed login attempts.
        """

        events = self.create_failed_attempts(count=5)

        events.append(
            self.create_event(
                timestamp=self.start_time + timedelta(seconds=15),
                event_type="SUCCESS_LOGIN"
            )
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 2)

        self.assertEqual(
            alerts[0]["alert_type"],
            "POSSIBLE_BRUTE_FORCE"
        )

        self.assertEqual(
            alerts[1]["alert_type"],
            "POSSIBLE_ACCOUNT_COMPROMISE"
        )

        self.assertEqual(
            alerts[1]["severity"],
            "CRITICAL"
        )

        self.assertEqual(
            alerts[1]["first_attempt"],
            self.start_time
        )

    # --------------------------------------------------
    # Test 6: Ignore late successful logins
    # --------------------------------------------------

    def test_no_compromise_alert_after_time_window(self):
        """
        Do not generate a compromise alert when
        the successful login occurs too late.
        """

        events = self.create_failed_attempts(count=5)

        events.append(
            self.create_event(
                timestamp=self.start_time + timedelta(minutes=5),
                event_type="SUCCESS_LOGIN"
            )
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)

        self.assertEqual(
            alerts[0]["alert_type"],
            "POSSIBLE_BRUTE_FORCE"
        )

    # --------------------------------------------------
    # Test 7: Prevent duplicate alerts
    # --------------------------------------------------

    def test_no_duplicate_alerts(self):
        """
        Avoid generating duplicate brute-force alerts
        for the same active attack.
        """

        events = self.create_failed_attempts(count=8)

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)

    # --------------------------------------------------
    # Test 8: Reset attempts after successful login
    # --------------------------------------------------

    def test_successful_login_resets_failed_attempts(self):
        """
        A successful login should reset the failed
        login history for that IP/account combination.
        """

        events = self.create_failed_attempts(count=4)

        events.append(
            self.create_event(
                timestamp=self.start_time + timedelta(seconds=10),
                event_type="SUCCESS_LOGIN"
            )
        )

        events.append(
            self.create_event(
                timestamp=self.start_time + timedelta(seconds=12),
                event_type="FAILED_LOGIN"
            )
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    # --------------------------------------------------
    # Test 9: Handle unsorted authentication events
    # --------------------------------------------------

    def test_unsorted_events(self):
        """Verify that events are processed chronologically."""

        events = self.create_failed_attempts(count=5)

        events.reverse()

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)

    # --------------------------------------------------
    # Test 10: Handle empty authentication logs
    # --------------------------------------------------

    def test_empty_events(self):
        """Verify that empty event lists are handled safely."""

        alerts = detect_brute_force([])

        self.assertEqual(alerts, [])

    # --------------------------------------------------
    # Test 11: Reject invalid detection settings
    # --------------------------------------------------

    def test_invalid_threshold(self):
        """Reject detection thresholds below one."""

        with self.assertRaises(ValueError):
            detect_brute_force([], threshold=0)

    def test_invalid_time_window(self):
        """Reject nonpositive detection windows."""

        with self.assertRaises(ValueError):
            detect_brute_force([], window_seconds=0)

    # --------------------------------------------------
    # Test 13: Separate authentication accounts
    # --------------------------------------------------

    def test_separate_user_accounts(self):
        """
        Failed attempts against different accounts
        should be tracked independently.
        """

        events = self.create_failed_attempts(
            count=4,
            username="admin"
        )

        events += self.create_failed_attempts(
            count=4,
            username="guest"
        )

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)

    # --------------------------------------------------
    # Test 14: Detect configurable thresholds
    # --------------------------------------------------

    def test_custom_detection_threshold(self):
        """Verify that custom thresholds are supported."""

        events = self.create_failed_attempts(count=3)

        alerts = detect_brute_force(
            events,
            threshold=3,
            window_seconds=60
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts"], 3)


if __name__ == "__main__":
    unittest.main()