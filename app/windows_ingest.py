
"""Import real Windows authentication activity into AllamSec."""

import argparse
from pathlib import Path

from app.windows_event_collector import (
    collect_windows_events,
    read_windows_xml_file,
)
from database.db_manager import (
    DEFAULT_DB_PATH,
    initialize_database,
    save_alerts,
    save_events,
)
from detection.brute_force import detect_brute_force
from detection.risk_scoring import score_alerts


def ingest_windows_events(
    events,
    db_path=DEFAULT_DB_PATH,
    threshold=5,
    window_seconds=60,
):
    """Store all events; detect attacks only on remote failures."""

    initialize_database(db_path)

    events = sorted(
        events,
        key=lambda event: event["timestamp"],
    )

    # Keep local/service activity in the event database.
    # Only remote authentication activity is eligible
    # for the existing IP-based brute-force detector.
    remote_events = [
        event for event in events
        if event.get("is_remote_authentication", False)
        and event.get("username") not in ("", "-", "UNKNOWN")
    ]

    alerts = detect_brute_force(
        remote_events,
        threshold=threshold,
        window_seconds=window_seconds,
    )

    scored_alerts = score_alerts(alerts)

    saved_events = save_events(
        events,
        "authentication",
        db_path=db_path,
    )

    saved_alerts = save_alerts(
        scored_alerts,
        db_path=db_path,
    )

    return {
        "collected_events": len(events),
        "remote_events": len(remote_events),
        "local_events": len(events) - len(remote_events),
        "saved_events": saved_events,
        "detected_alerts": len(scored_alerts),
        "saved_alerts": saved_alerts,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Import Windows Security logs into AllamSec."
    )

    source = parser.add_mutually_exclusive_group(
        required=True
    )

    source.add_argument(
        "--live",
        action="store_true",
        help="Collect Windows Security events.",
    )

    source.add_argument(
        "--file",
        type=Path,
        help="Read a saved Windows event XML file.",
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=500,
    )

    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
    )

    args = parser.parse_args()

    print("=" * 55)
    print("ALLAMSEC - WINDOWS SECURITY LOG INGESTION")
    print("=" * 55)

    try:
        if args.live:
            events, invalid = collect_windows_events(
                max_events=args.max_events
            )
        else:
            events, invalid = read_windows_xml_file(
                args.file
            )

        results = ingest_windows_events(
            events,
            db_path=args.db,
        )

    except (RuntimeError, OSError, ValueError) as exc:
        parser.exit(1, f"Error: {exc}\n")

    print(f"Normalized events: {results['collected_events']}")
    print(f"Local/service events: {results['local_events']}")
    print(f"Remote authentication events: {results['remote_events']}")
    print(f"New database events: {results['saved_events']}")
    print(f"Detected alerts: {results['detected_alerts']}")
    print(f"New database alerts: {results['saved_alerts']}")
    print(f"Malformed XML events: {invalid}")

    print("=" * 55)
    print("Windows ingestion complete.")
    print("=" * 55)


if __name__ == "__main__":
    main()
