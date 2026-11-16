
"""Verify monitoring failures return unsuccessful exit codes."""

import unittest
from unittest.mock import patch

from app.windows_monitor import monitor_windows
from app.monitor_launcher import main as launcher_main


class TestMonitorFailureExit(unittest.TestCase):

    @patch("app.windows_monitor.process_windows_batch")
    def test_finite_monitor_propagates_collection_error(
        self,
        mock_batch,
    ):
        mock_batch.side_effect = RuntimeError(
            "Access is denied."
        )

        with self.assertRaises(RuntimeError):
            monitor_windows(
                interval=5,
                max_events=10,
                max_cycles=1,
            )

    @patch("app.monitor_launcher.monitor_windows")
    @patch("sys.argv", ["monitor_launcher", "--cycles", "1"])
    def test_launcher_returns_failure_exit_code(
        self,
        mock_monitor,
    ):
        mock_monitor.side_effect = RuntimeError(
            "Access is denied."
        )

        result = launcher_main()

        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
