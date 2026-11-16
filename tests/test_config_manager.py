
"""Tests for AllamSec configuration management."""

import json
import tempfile
import unittest

from copy import deepcopy
from pathlib import Path

from app.config_manager import (
    DEFAULT_CONFIG,
    load_config,
    validate_config,
)


class TestConfigManager(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.config_path = (
            Path(self.temp.name) / "config.json"
        )

    def write_config(self, config):
        with self.config_path.open(
            "w", encoding="utf-8"
        ) as file:
            json.dump(config, file)

    def test_valid_configuration(self):
        config = deepcopy(DEFAULT_CONFIG)
        self.assertEqual(validate_config(config), config)

    def test_load_configuration(self):
        self.write_config(deepcopy(DEFAULT_CONFIG))

        result = load_config(self.config_path)

        self.assertEqual(
            result["monitoring"]["interval_seconds"],
            60,
        )

    def test_invalid_interval(self):
        config = deepcopy(DEFAULT_CONFIG)
        config["monitoring"]["interval_seconds"] = 1

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_invalid_event_limit(self):
        config = deepcopy(DEFAULT_CONFIG)
        config["monitoring"]["max_events"] = 0

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_invalid_threshold(self):
        config = deepcopy(DEFAULT_CONFIG)
        config["detection"]["brute_force_threshold"] = 0

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_invalid_window(self):
        config = deepcopy(DEFAULT_CONFIG)
        config["detection"]["window_seconds"] = -10

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_invalid_severity(self):
        config = deepcopy(DEFAULT_CONFIG)
        config["notifications"]["minimum_severity"] = "EXTREME"

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_invalid_email_boolean(self):
        config = deepcopy(DEFAULT_CONFIG)
        config["notifications"]["email_enabled"] = "yes"

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_reject_network_host(self):
        config = deepcopy(DEFAULT_CONFIG)
        config["dashboard"]["host"] = "0.0.0.0"

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_invalid_json(self):
        self.config_path.write_text(
            "{ invalid json",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            load_config(self.config_path)

    def test_missing_custom_config(self):
        with self.assertRaises(FileNotFoundError):
            load_config(self.config_path)

    def test_missing_section(self):
        config = deepcopy(DEFAULT_CONFIG)
        del config["dashboard"]

        with self.assertRaises(ValueError):
            validate_config(config)


if __name__ == "__main__":
    unittest.main()
