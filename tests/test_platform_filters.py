
"""Integration tests for AllamSec platform filtering."""

import json
import tempfile
import unittest
from pathlib import Path

from dashboard.web_app import create_app
from database.db_manager import (
    initialize_database,
    save_events,
)


class TestPlatformFilters(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = (
            Path(self.temp_dir.name) / "platform_test.db"
        )

        initialize_database(db_path=self.db_path)

        self.app = create_app(db_path=self.db_path)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.windows_event = {
            "timestamp": "2026-11-08T10:00:00",
            "event_type": "FAILED_LOGIN",
            "username": "windows_user",
            "ip_address": "192.168.1.10",
            "event_origin": "windows_security",
            "windows_event_id": 4625,
            "windows_record_id": 10001,
            "computer": "TEST-PC",
        }

        self.linux_event = {
            "timestamp": "2026-11-08T10:01:00",
            "event_type": "FAILED_LOGIN",
            "username": "linux_user",
            "ip_address": "192.168.1.20",
            "event_origin": "linux_ssh",
            "computer": "ubuntu-test",
        }

        self.other_event = {
            "timestamp": "2026-11-08T10:02:00",
            "event_type": "SUCCESS_LOGIN",
            "username": "sample_user",
            "ip_address": "192.168.1.30",
        }

        save_events(
            [
                self.windows_event,
                self.linux_event,
                self.other_event,
            ],
            event_source="authentication",
            db_path=self.db_path,
        )

    def get_page(self, platform="all", source="all"):
        return self.client.get(
            "/events",
            query_string={
                "source": source,
                "platform": platform,
            },
        )

    def test_all_platforms(self):
        response = self.get_page()

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        self.assertIn("windows_user", html)
        self.assertIn("linux_user", html)
        self.assertIn("sample_user", html)

    def test_windows_filter(self):
        response = self.get_page(platform="windows")

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        self.assertIn("windows_user", html)
        self.assertNotIn("linux_user", html)
        self.assertNotIn("sample_user", html)

    def test_linux_filter(self):
        response = self.get_page(platform="linux")

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        self.assertIn("linux_user", html)
        self.assertNotIn("windows_user", html)
        self.assertNotIn("sample_user", html)

    def test_other_filter(self):
        response = self.get_page(platform="other")

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        self.assertIn("sample_user", html)
        self.assertNotIn("windows_user", html)
        self.assertNotIn("linux_user", html)

    def test_authentication_and_linux(self):
        response = self.get_page(
            platform="linux",
            source="authentication",
        )

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        self.assertIn("linux_user", html)
        self.assertNotIn("windows_user", html)

    def test_invalid_platform(self):
        response = self.get_page(
            platform="unsupported",
        )

        self.assertEqual(response.status_code, 400)

    def test_platform_dropdown(self):
        response = self.get_page()

        html = response.get_data(as_text=True)

        self.assertIn('name="platform"', html)
        self.assertIn("Linux SSH", html)
        self.assertIn("Windows Security", html)

    def test_platform_column(self):
        response = self.get_page()

        html = response.get_data(as_text=True)

        self.assertIn("<th>PLATFORM</th>", html)


if __name__ == "__main__":
    unittest.main()
