
"""Tests for the AllamSec dashboard server."""

import unittest
from unittest.mock import patch

from dashboard.server import main


class TestDashboardServer(unittest.TestCase):

    @patch("dashboard.server.serve")
    @patch("dashboard.server.load_config")
    @patch("sys.argv", ["dashboard.server"])
    def test_server_uses_configured_port(
        self,
        mock_load_config,
        mock_serve,
    ):
        mock_load_config.return_value = {
            "dashboard": {
                "host": "127.0.0.1",
                "port": 5050,
            }
        }

        result = main()

        self.assertEqual(result, 0)

        self.assertEqual(
            mock_serve.call_args.kwargs["host"],
            "127.0.0.1",
        )

        self.assertEqual(
            mock_serve.call_args.kwargs["port"],
            5050,
        )

        self.assertEqual(
            mock_serve.call_args.kwargs["threads"],
            4,
        )

    @patch("dashboard.server.serve")
    @patch("dashboard.server.load_config")
    @patch("sys.argv", ["dashboard.server"])
    def test_invalid_configuration_prevents_startup(
        self,
        mock_load_config,
        mock_serve,
    ):
        mock_load_config.side_effect = ValueError(
            "Invalid dashboard configuration."
        )

        result = main()

        self.assertEqual(result, 1)
        mock_serve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
