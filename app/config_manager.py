
"""Configuration management for AllamSec."""

import json
from copy import deepcopy
from pathlib import Path


from app.paths import DATA_ROOT, DEFAULT_CONFIG_PATH

DEFAULT_CONFIG = {
    "monitoring": {
        "interval_seconds": 60,
        "max_events": 500,
        "checkpoint_path": "database/windows_checkpoint.json",
    },
    "detection": {
        "brute_force_threshold": 5,
        "window_seconds": 60,
    },
    "notifications": {
        "email_enabled": False,
        "minimum_severity": "HIGH",
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 5000,
    },
}


def validate_config(config):
    """Validate AllamSec configuration values."""

    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object.")

    if set(config) != set(DEFAULT_CONFIG):
        raise ValueError(
            "Configuration must contain exactly these sections: "
            + ", ".join(DEFAULT_CONFIG)
        )

    for section, expected in DEFAULT_CONFIG.items():
        actual = config[section]

        if not isinstance(actual, dict):
            raise ValueError(
                f"Configuration section '{section}' must be an object."
            )

        if set(actual) != set(expected):
            raise ValueError(
                f"Invalid or missing settings in '{section}'."
            )

    monitoring = config["monitoring"]
    detection = config["detection"]
    notifications = config["notifications"]
    dashboard = config["dashboard"]

    def check_integer(value, name, minimum, maximum):
        if (
            type(value) is not int
            or not minimum <= value <= maximum
        ):
            raise ValueError(
                f"{name} must be an integer between "
                f"{minimum} and {maximum}."
            )

    check_integer(
        monitoring["interval_seconds"],
        "monitoring.interval_seconds",
        5,
        86400,
    )

    check_integer(
        monitoring["max_events"],
        "monitoring.max_events",
        1,
        10000,
    )

    checkpoint = monitoring["checkpoint_path"]

    if not isinstance(checkpoint, str) or not checkpoint.strip():
        raise ValueError(
            "monitoring.checkpoint_path must be a nonempty string."
        )

    check_integer(
        detection["brute_force_threshold"],
        "detection.brute_force_threshold",
        1,
        10000,
    )

    check_integer(
        detection["window_seconds"],
        "detection.window_seconds",
        1,
        86400,
    )

    if type(notifications["email_enabled"]) is not bool:
        raise ValueError(
            "notifications.email_enabled must be true or false."
        )

    if notifications["minimum_severity"] not in (
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ):
        raise ValueError(
            "Invalid notification minimum severity."
        )

    # Keep the dashboard local-only for this release.
    if dashboard["host"] != "127.0.0.1":
        raise ValueError(
            "Dashboard host must be 127.0.0.1 for local mode."
        )

    check_integer(
        dashboard["port"],
        "dashboard.port",
        1,
        65535,
    )

    return config


def load_config(config_path=DEFAULT_CONFIG_PATH):
    """Load and validate the AllamSec configuration."""

    path = Path(config_path)

    if not path.exists():
        if path == DEFAULT_CONFIG_PATH:
            return deepcopy(DEFAULT_CONFIG)

        raise FileNotFoundError(
            f"Configuration file not found: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            config = json.load(file)

    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON configuration: {exc}"
        ) from exc

    return validate_config(config)



def resolve_checkpoint_path(config):
    """Resolve the checkpoint relative to writable application data."""

    value = Path(config["monitoring"]["checkpoint_path"])

    if value.is_absolute():
        return value

    return DATA_ROOT / value