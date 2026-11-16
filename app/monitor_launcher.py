
"""Start AllamSec monitoring using validated configuration."""

import argparse
import sys

from app.config_manager import (
    DEFAULT_CONFIG_PATH,
    load_config,
    resolve_checkpoint_path,
)
from app.windows_monitor import monitor_windows


def main():
    parser = argparse.ArgumentParser(
        description="Launch AllamSec Windows monitoring."
    )

    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to AllamSec configuration JSON.",
    )

    parser.add_argument(
        "--cycles",
        type=int,
        default=None,
        help="Optional number of monitoring cycles.",
    )

    args = parser.parse_args()

    try:
        config = load_config(args.config)

        if args.cycles is not None and args.cycles < 1:
            raise ValueError("--cycles must be at least 1.")

        monitoring = config["monitoring"]
        detection = config["detection"]
        notifications = config["notifications"]

        print("=" * 50)
        print("ALLAMSEC WINDOWS MONITOR")
        print("=" * 50)
        print(
            "Interval:",
            monitoring["interval_seconds"],
            "seconds",
        )
        print(
            "Maximum events:",
            monitoring["max_events"],
        )
        print(
            "Checkpoint:",
            resolve_checkpoint_path(config),
        )
        print("=" * 50)

        monitor_windows(
            interval=monitoring["interval_seconds"],
            max_events=monitoring["max_events"],
            max_cycles=args.cycles,
            checkpoint_path=resolve_checkpoint_path(config),
            detection_threshold=detection["brute_force_threshold"],
            detection_window=detection["window_seconds"],
            email_enabled=notifications["email_enabled"],
            minimum_severity=notifications["minimum_severity"],
        )

    except (ValueError, OSError, RuntimeError) as exc:
        print(
            f"AllamSec configuration error: {exc}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
