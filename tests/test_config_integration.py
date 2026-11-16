
"""Tests for AllamSec configuration integration."""

import unittest
from unittest.mock import patch

from app.config_manager import DEFAULT_CONFIG
from app.monitor_launcher import main as launcher_main


class TestConfigIntegration(unittest.TestCase):

    @patch("app.monitor_launcher.monitor_windows")
    @patch("app.monitor_launcher.resolve_checkpoint_path")
    @patch("app.monitor_launcher.load_config")
    @patch("sys.argv", ["monitor_launcher", "--cycles", "1"])
    def test_monitor_receives_configuration(
        self,
        mock_load,
        mock_checkpoint,
        mock_monitor,
    ):
        config = {
            section: values.copy()
            for section, values in DEFAULT_CONFIG.items()
        }

        config["detection"]["brute_force_threshold"] = 8
        config["detection"]["window_seconds"] = 120
        config["notifications"]["minimum_severity"] = "CRITICAL"

        mock_load.return_value = config
        mock_checkpoint.return_value = "test_checkpoint.json"

        result = launcher_main()

        self.assertEqual(result, 0)

        mock_monitor.assert_called_once_with(
            interval=60,
            max_events=500,
            max_cycles=1,
            checkpoint_path="test_checkpoint.json",
            detection_threshold=8,
            detection_window=120,
            email_enabled=False,
            minimum_severity="CRITICAL",
        )

    @patch("app.monitor_launcher.monitor_windows")
    @patch("app.monitor_launcher.load_config")
    @patch("sys.argv", ["monitor_launcher", "--cycles", "0"])
    def test_invalid_cycle_count(
        self,
        mock_load,
        mock_monitor,
    ):
        mock_load.return_value = DEFAULT_CONFIG

        result = launcher_main()

        self.assertEqual(result, 1)
        mock_monitor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
