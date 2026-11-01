import unittest
from datetime import datetime

from app.network_parser import parse_network_line


class TestNetworkParser(unittest.TestCase):

    def setUp(self):
        self.valid_line = (
            "2026-10-28 13:00:01 BLOCKED "
            "src=192.168.1.100 dst=192.168.1.50 port=443"
        )

    def test_valid_network_event(self):
        event = parse_network_line(self.valid_line)

        self.assertIsNotNone(event)
        self.assertEqual(event["status"], "BLOCKED")
        self.assertEqual(event["source_ip"], "192.168.1.100")
        self.assertEqual(event["destination_ip"], "192.168.1.50")
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(
            event["timestamp"],
            datetime(2026, 10, 28, 13, 0, 1),
        )

    def test_valid_ipv6(self):
        line = (
            "2026-10-28 13:00:01 ALLOWED "
            "src=2001:db8::1 dst=2001:db8::2 port=443"
        )
        self.assertIsNotNone(parse_network_line(line))

    def test_invalid_source_ip(self):
        line = self.valid_line.replace(
            "192.168.1.100", "999.999.999.999"
        )
        self.assertIsNone(parse_network_line(line))

    def test_invalid_destination_ip(self):
        line = self.valid_line.replace(
            "192.168.1.50", "999.999.999.999"
        )
        self.assertIsNone(parse_network_line(line))

    def test_invalid_port_zero(self):
        line = self.valid_line.replace("port=443", "port=0")
        self.assertIsNone(parse_network_line(line))

    def test_invalid_port_too_large(self):
        line = self.valid_line.replace("port=443", "port=70000")
        self.assertIsNone(parse_network_line(line))

    def test_invalid_status(self):
        line = self.valid_line.replace("BLOCKED", "UNKNOWN")
        self.assertIsNone(parse_network_line(line))

    def test_invalid_timestamp(self):
        line = self.valid_line.replace("13:00:01", "99:00:01")
        self.assertIsNone(parse_network_line(line))

    def test_missing_fields(self):
        line = (
            "2026-10-28 13:00:01 BLOCKED "
            "src=192.168.1.100"
        )
        self.assertIsNone(parse_network_line(line))

    def test_extra_fields(self):
        self.assertIsNone(
            parse_network_line(self.valid_line + " extra=value")
        )

    def test_empty_line(self):
        self.assertIsNone(parse_network_line(""))

    def test_valid_port_boundaries(self):
        for port in (1, 65535):
            with self.subTest(port=port):
                line = self.valid_line.replace(
                    "port=443", f"port={port}"
                )
                self.assertIsNotNone(parse_network_line(line))


if __name__ == "__main__":
    unittest.main()