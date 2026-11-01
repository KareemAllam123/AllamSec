import unittest
from datetime import datetime, timedelta

from detection.port_scan import detect_port_scans


class TestPortScanDetection(unittest.TestCase):

    def setUp(self):
        self.start = datetime(2026, 10, 28, 13, 0, 0)

    def create_events(
        self,
        ports,
        interval=1,
        source="192.168.1.100",
        destination="192.168.1.50",
    ):
        events = []

        for index, port in enumerate(ports):
            events.append({
                "timestamp": self.start + timedelta(
                    seconds=index * interval
                ),
                "status": "BLOCKED",
                "source_ip": source,
                "destination_ip": destination,
                "destination_port": port,
            })

        return events

    def test_detects_port_scan(self):
        events = self.create_events(range(20, 30))
        alerts = detect_port_scans(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "POSSIBLE_PORT_SCAN")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["unique_ports"], 10)

    def test_no_alert_below_threshold(self):
        events = self.create_events(range(20, 29))
        self.assertEqual(detect_port_scans(events), [])

    def test_duplicate_ports_not_counted(self):
        events = self.create_events([22] * 15)
        self.assertEqual(detect_port_scans(events), [])

    def test_outside_time_window(self):
        events = self.create_events(range(20, 30), interval=10)
        self.assertEqual(detect_port_scans(events), [])

    def test_multiple_attackers(self):
        events = self.create_events(range(20, 30))
        events += self.create_events(
            range(30, 40), source="192.168.1.200"
        )
        self.assertEqual(len(detect_port_scans(events)), 2)

    def test_separate_destinations(self):
        events = self.create_events(range(20, 25))
        events += self.create_events(
            range(25, 30), destination="192.168.1.60"
        )
        self.assertEqual(detect_port_scans(events), [])

    def test_unsorted_events(self):
        events = self.create_events(range(20, 30))
        events.reverse()
        self.assertEqual(len(detect_port_scans(events)), 1)

    def test_critical_severity(self):
        events = self.create_events(range(20, 40))
        alerts = detect_port_scans(events, threshold=20)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_no_duplicate_alerts(self):
        events = self.create_events(range(20, 35))
        self.assertEqual(len(detect_port_scans(events)), 1)

    def test_empty_events(self):
        self.assertEqual(detect_port_scans([]), [])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_port_scans([], threshold=0)

    def test_invalid_window(self):
        with self.assertRaises(ValueError):
            detect_port_scans([], window_seconds=0)

    def test_custom_threshold(self):
        events = self.create_events([22, 80, 443])
        alerts = detect_port_scans(events, threshold=3)
        self.assertEqual(len(alerts), 1)


if __name__ == "__main__":
    unittest.main()