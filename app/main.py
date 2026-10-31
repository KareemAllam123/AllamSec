from datetime import datetime
from pathlib import Path

from app.parser import read_log_file
from app.analyzer import (
    analyze_authentication_events,
    display_report
)
from detection.brute_force import (
    detect_brute_force,
    display_security_alerts
)


# Project directories
BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = (
    BASE_DIR
    / "data"
    / "sample_logs"
    / "authentication.log"
)

# Detection settings
BRUTE_FORCE_THRESHOLD = 5
DETECTION_WINDOW_SECONDS = 60

# Application information
APP_NAME = "AllamSec"
APP_VERSION = "0.3.0"


def display_banner():
    """Display the AllamSec application banner."""

    print("=" * 55)
    print(f"{APP_NAME:^55}")
    print(f"{'Security Monitoring & Threat Detection':^55}")
    print("=" * 55)


def initialize_system():
    """Initialize the AllamSec monitoring system."""

    print(f"\nInitializing {APP_NAME}...")

    current_time = datetime.now()

    print(f"System started at: {current_time:%Y-%m-%d %H:%M:%S}")
    print("System Status: ONLINE")
    print("Monitoring Mode: DEVELOPMENT")
    print("Log Source: Local Authentication Logs")
    print(f"Project Version: {APP_VERSION}")

    print("\nInitialization complete.")


def main():
    """Run the AllamSec security monitoring application."""

    display_banner()
    initialize_system()

    # Step 1: Load authentication logs
    print("\nLoading authentication logs...")

    if not LOG_FILE.is_file():
        print(f"Error: Log file not found: {LOG_FILE}")
        return

    events, invalid_lines = read_log_file(LOG_FILE)

    print(f"Successfully loaded {len(events)} valid events.")

    # Step 2: Analyze authentication activity
    statistics = analyze_authentication_events(events)

    display_report(statistics, invalid_lines)

    # Step 3: Run threat detection
    print("\nRunning threat detection engine...")

    alerts = detect_brute_force(
        events,
        threshold=BRUTE_FORCE_THRESHOLD,
        window_seconds=DETECTION_WINDOW_SECONDS
    )

    # Step 4: Display security alerts
    display_security_alerts(alerts)


if __name__ == "__main__":
    main()