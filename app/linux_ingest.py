
"""Linux SSH authentication ingestion for AllamSec."""

import argparse

from app.linux_event_collector import read_linux_auth_file
from database.db_manager import (
    initialize_database,
    save_events,
    save_alerts,
)
from detection.brute_force import detect_brute_force
from detection.risk_scoring import score_alerts


def ingest_linux_file(file_path, year=None, db_path=None):
    """Parse, analyze, and save Linux SSH authentication logs."""

    events, invalid_lines = read_linux_auth_file(
        file_path,
        year=year,
    )

    failed_events = [
        event for event in events
        if event["event_type"] == "FAILED_LOGIN"
    ]

    successful_events = [
        event for event in events
        if event["event_type"] == "SUCCESS_LOGIN"
    ]

    alerts = detect_brute_force(
        events,
        threshold=5,
        window_seconds=60,
    )

    scored_alerts = score_alerts(alerts)

    # Use the existing AllamSec database functions.
    if db_path is None:
        initialize_database()
        saved_events = save_events(
            events,
            event_source="authentication",
        )
        saved_alerts = save_alerts(scored_alerts)
    else:
        initialize_database(db_path=db_path)
        saved_events = save_events(
            events,
            event_source="authentication",
            db_path=db_path,
        )
        saved_alerts = save_alerts(
            scored_alerts,
            db_path=db_path,
        )

    return {
        "collected_events": len(events),
        "failed_logins": len(failed_events),
        "successful_logins": len(successful_events),
        "invalid_lines": invalid_lines,
        "detected_alerts": len(scored_alerts),
        "saved_events": saved_events,
        "saved_alerts": saved_alerts,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Ingest Linux SSH logs into AllamSec."
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Path to a Linux authentication log.",
    )

    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year used for syslog timestamps.",
    )

    args = parser.parse_args()

    results = ingest_linux_file(
        args.file,
        year=args.year,
    )

    print("=" * 55)
    print("ALLAMSEC - LINUX SSH LOG INGESTION")
    print("=" * 55)
    print("Normalized events:", results["collected_events"])
    print("Failed logins:", results["failed_logins"])
    print("Successful logins:", results["successful_logins"])
    print("Malformed lines:", results["invalid_lines"])
    print("New database events:", results["saved_events"])
    print("Detected alerts:", results["detected_alerts"])
    print("New database alerts:", results["saved_alerts"])
    print("=" * 55)
    print("Linux ingestion complete.")
    print("=" * 55)


if __name__ == "__main__":
    main()
