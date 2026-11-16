
"""Production-oriented local dashboard server for AllamSec."""

import argparse
import logging
import sys

from waitress import serve

from app.config_manager import (
    DEFAULT_CONFIG_PATH,
    load_config,
)
from dashboard.web_app import app


logger = logging.getLogger("AllamSec.dashboard")


def main():
    parser = argparse.ArgumentParser(
        description="Start the AllamSec local dashboard."
    )

    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to the AllamSec configuration file.",
    )

    args = parser.parse_args()

    try:
        config = load_config(args.config)
        dashboard = config["dashboard"]

        host = dashboard["host"]
        port = dashboard["port"]

        print("=" * 55)
        print("ALLAMSEC SECURITY DASHBOARD")
        print("=" * 55)
        print(f"Dashboard: http://{host}:{port}")
        print("Server: Waitress")
        print("Press CTRL+C to stop.")
        print("=" * 55, flush=True)

        serve(
            app,
            host=host,
            port=port,
            threads=4,
        )

    except (ValueError, OSError) as exc:
        logger.error("Dashboard startup failed: %s", exc)
        print(
            f"AllamSec startup error: {exc}",
            file=sys.stderr,
        )
        return 1

    except KeyboardInterrupt:
        print("\nAllamSec dashboard stopped.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
