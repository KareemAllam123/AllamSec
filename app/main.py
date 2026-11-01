from datetime import datetime
from pathlib import Path

from app.parser import read_log_file
from app.analyzer import (
    analyze_authentication_events,
    display_report,
)
from app.network_parser import read_network_log

from detection.brute_force import (
    detect_brute_force,
    display_security_alerts,
)
from detection.port_scan import (
    detect_port_scans,
    display_network_alerts,
)


BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_LOG_FILE = (
    BASE_DIR / "data" / "sample_logs" / "authentication.log"
)

NETWORK_LOG_FILE = (
    BASE_DIR / "data" / "sample_logs" / "network.log"
)

BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 10
DETECTION_WINDOW_SECONDS = 60

APP_NAME = "AllamSec"
APP_VERSION = "0.4.0"


def display_banner():
    print("=" * 55)
    print(f"{APP_NAME:^55}")
    print(f"{'Security Monitoring & Threat Detection':^55}")
    print("=" * 55)


def initialize_system():
    print(f"\nInitializing {APP_NAME}...")
    current_time = datetime.now()
    print(f"System started at: {current_time:%Y-%m-%d %H:%M:%S}")
    print("System Status: ONLINE")
    print("Monitoring Mode: DEVELOPMENT")
    print("Log Sources: Authentication and Network Logs")
    print(f"Project Version: {APP_VERSION}")
    print("\nInitialization complete.")


def monitor_authentication():
    print("\nLoading authentication logs...")

    if not AUTH_LOG_FILE.is_file():
        print(f"Authentication log not found: {AUTH_LOG_FILE}")
        return []

    events, invalid_lines = read_log_file(AUTH_LOG_FILE)
    print(f"Successfully loaded {len(events)} authentication events.")

    statistics = analyze_authentication_events(events)
    display_report(statistics, invalid_lines)

    print("\nRunning authentication threat detection...")

    alerts = detect_brute_force(
        events,
        threshold=BRUTE_FORCE_THRESHOLD,
        window_seconds=DETECTION_WINDOW_SECONDS,
    )

    display_security_alerts(alerts)
    return alerts


def monitor_network():
    print("\nLoading network connection logs...")

    if not NETWORK_LOG_FILE.is_file():
        print(f"Network log not found: {NETWORK_LOG_FILE}")
        return []

    events, invalid_lines = read_network_log(NETWORK_LOG_FILE)

    print(f"Successfully loaded {len(events)} network events.")
    print(f"Invalid Network Entries: {invalid_lines}")

    print("\nRunning network threat detection...")

    alerts = detect_port_scans(
        events,
        threshold=PORT_SCAN_THRESHOLD,
        window_seconds=DETECTION_WINDOW_SECONDS,
    )

    display_network_alerts(alerts)
    return alerts


def main():
    display_banner()
    initialize_system()

    authentication_alerts = monitor_authentication()
    network_alerts = monitor_network()

    total_alerts = len(authentication_alerts) + len(network_alerts)

    print("\n" + "=" * 60)
    print(f"{'AllamSec Monitoring Summary':^60}")
    print("=" * 60)
    print(f"Authentication Alerts: {len(authentication_alerts)}")
    print(f"Network Alerts:        {len(network_alerts)}")
    print(f"Total Security Alerts: {total_alerts}")
    print("=" * 60)


if __name__ == "__main__":
    main()