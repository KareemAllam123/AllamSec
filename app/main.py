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
from detection.risk_scoring import (
    score_alerts,
    display_risk_report,
)

from database.db_manager import (
    initialize_database,
    save_events,
    save_alerts,
    display_database_summary,
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
APP_VERSION = "0.7.0"

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

    initialize_database()

    print("Database Status: READY")
    print("\nInitialization complete.")


def monitor_authentication():
    print("\nLoading authentication logs...")

    if not AUTH_LOG_FILE.is_file():
        print(f"Authentication log not found: {AUTH_LOG_FILE}")
        return []

    events, invalid_lines = read_log_file(AUTH_LOG_FILE)

    print(f"Successfully loaded {len(events)} authentication events.")

    new_events = save_events(events, "authentication")
    print(f"New authentication events stored: {new_events}")

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

    new_events = save_events(events, "network")
    print(f"New network events stored: {new_events}")

    print("\nRunning network threat detection...")

    alerts = detect_port_scans(
        events,
        threshold=PORT_SCAN_THRESHOLD,
        window_seconds=DETECTION_WINDOW_SECONDS,
    )

    display_network_alerts(alerts)
    return alerts


def display_monitoring_summary(authentication_alerts, network_alerts):
    all_alerts = authentication_alerts + network_alerts
    prioritized_alerts = score_alerts(all_alerts)

    print("\n" + "=" * 60)
    print(f"{'AllamSec Monitoring Summary':^60}")
    print("=" * 60)

    print(f"Authentication Alerts: {len(authentication_alerts)}")
    print(f"Network Alerts:        {len(network_alerts)}")
    print(f"Total Security Alerts: {len(all_alerts)}")

    if prioritized_alerts:
        highest_risk = prioritized_alerts[0]

        print(f"Highest Risk Score:    {highest_risk['risk_score']}/100")
        print(f"Highest Severity:      {highest_risk['severity']}")
        print(f"Top Threat:            {highest_risk['alert_type']}")
    else:
        print("Highest Risk Score:    N/A")
        print("Highest Severity:      N/A")
        print("Top Threat:            None")

    print("=" * 60)


def main():
    display_banner()
    initialize_system()

    authentication_alerts = monitor_authentication()
    network_alerts = monitor_network()

    all_alerts = authentication_alerts + network_alerts
    prioritized_alerts = score_alerts(all_alerts)

    display_risk_report(all_alerts)

    new_alerts = save_alerts(prioritized_alerts)

    print(f"\nNew security alerts stored: {new_alerts}")

    display_monitoring_summary(
        authentication_alerts,
        network_alerts,
    )

    display_database_summary()


if __name__ == "__main__":
    main()