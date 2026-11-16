
"""Import Windows authentication activity into AllamSec."""

import argparse
import json

from datetime import datetime, timedelta
from pathlib import Path

from app.alert_dispatcher import dispatch_alerts

from app.windows_event_collector import (
    collect_windows_events,
    read_windows_xml_file,
)

from database.db_manager import (
    DEFAULT_DB_PATH,
    create_hash,
    database_connection,
    initialize_database,
    normalize_value,
    save_alerts,
    save_events,
)


from detection.brute_force import detect_brute_force
from detection.risk_scoring import score_alerts


def parse_timestamp(value):
    """Convert a supported event timestamp to datetime."""

    if isinstance(value, datetime):
        return value

    return datetime.fromisoformat(
        str(value).replace("Z", "+00:00")
    )


def is_remote_event(event):
    """Determine whether an event is eligible for detection."""

    return (
        event.get("is_remote_authentication", False)
        and event.get("username") not in (
            "", "-", "UNKNOWN", None
        )
        and bool(event.get("ip_address"))
    )


def get_event_hash(event):
    """Calculate the same identity used by save_events."""

    normalized = normalize_value(event)

    return create_hash({
        "source": "authentication",
        "event": normalized,
    })


def get_new_windows_events(events, db_path=DEFAULT_DB_PATH):
    """Find Windows events not already stored in SQLite.

    This is a read-only check. The caller must subsequently
    save the events before using them for detection.

    Duplicate records within the incoming batch are also
    excluded.
    """

    unique_events = {}

    for event in events:
        event_hash = get_event_hash(event)
        unique_events[event_hash] = event

    if not unique_events:
        return []

    new_events = []

    with database_connection(db_path) as connection:
        for event_hash, event in unique_events.items():

            existing = connection.execute("""
                SELECT 1
                FROM security_events
                WHERE event_hash = ?
            """, (event_hash,)).fetchone()

            if existing is None:
                new_events.append(event)

    return new_events



def get_windows_event_history(
    start_time,
    end_time,
    db_path=DEFAULT_DB_PATH,
):
    """Retrieve Windows authentication events in a time range."""

    start_value = parse_timestamp(start_time).isoformat()
    end_value = parse_timestamp(end_time).isoformat()

    with database_connection(db_path) as connection:
        rows = connection.execute("""
            SELECT event_data
            FROM security_events
            WHERE event_source = 'authentication'
              AND event_timestamp >= ?
              AND event_timestamp <= ?
              AND json_extract(
                    event_data,
                    '$.event_origin'
                  ) = 'windows_security'
            ORDER BY event_timestamp ASC
        """, (start_value, end_value)).fetchall()

    history = []

    for row in rows:
        event = json.loads(row["event_data"])

        if is_remote_event(event):
            history.append(event)

    return history


def recover_windows_detection(
    events,
    db_path=DEFAULT_DB_PATH,
    threshold=5,
    window_seconds=60,
):
    """Recheck stored Windows activity after interrupted ingestion.

    This recovery pass detects attacks involving the supplied
    event window and relies on persistent alert deduplication
    to avoid inserting duplicate alerts.

    It does not send emails or advance checkpoints.
    """

    initialize_database(db_path)

    if not events:
        return {
            "recovered_alerts": 0,
            "existing_alerts": 0,
        }

    remote_events = [
        event for event in events
        if is_remote_event(event)
    ]

    if not remote_events:
        return {
            "recovered_alerts": 0,
            "existing_alerts": 0,
        }

    timestamps = [
        parse_timestamp(event["timestamp"])
        for event in remote_events
    ]

    start_time = (
        min(timestamps)
        - timedelta(seconds=window_seconds)
    )

    end_time = max(timestamps)

    history = get_windows_event_history(
        start_time,
        end_time,
        db_path=db_path,
    )

    unique_events = {}

    for event in history:
        unique_events[get_event_hash(event)] = event

    normalized_events = []

    for event in unique_events.values():
        normalized = event.copy()
        normalized["timestamp"] = parse_timestamp(
            event["timestamp"]
        )
        normalized_events.append(normalized)

    alerts = detect_brute_force(
        normalized_events,
        threshold=threshold,
        window_seconds=window_seconds,
    )

    scored_alerts = score_alerts(alerts)

    # The database's alert hashes prevent repeated inserts.
    saved = save_alerts(
        scored_alerts,
        db_path=db_path,
    )

    return {
        "recovered_alerts": saved,
        "existing_alerts": len(scored_alerts) - saved,
    }



def ingest_windows_events(
    events,
    db_path=DEFAULT_DB_PATH,
    threshold=5,
    window_seconds=60,
    email_enabled=False,
    minimum_severity="HIGH",
):
    """Store Windows events and detect attacks across batches."""

    if threshold < 1:
        raise ValueError(
            "Detection threshold must be at least 1."
        )

    if window_seconds <= 0:
        raise ValueError(
            "Detection window must be positive."
        )

    initialize_database(db_path)

    events = sorted(
        events,
        key=lambda event: parse_timestamp(
            event["timestamp"]
        ),
    )

    remote_events = [
        event for event in events
        if is_remote_event(event)
    ]


    # Identify genuinely new remote events BEFORE saving
    # the incoming batch to SQLite.
    new_remote_events = get_new_windows_events(
        remote_events,
        db_path=db_path,
    )

    # Persist the complete batch.
    # SQLite prevents duplicate event hashes.
    saved_events = save_events(
        events,
        "authentication",
        db_path=db_path,
    )

    detection_events = list(remote_events)


    if remote_events:
        timestamps = [
            parse_timestamp(event["timestamp"])
            for event in remote_events
        ]

        # Retrieve events from before the earliest
        # incoming event, allowing an attack to span
        # multiple collection cycles.
        start_time = (
            min(timestamps)
            - timedelta(seconds=window_seconds)
        )

        end_time = max(timestamps)

        history = get_windows_event_history(
            start_time,
            end_time,
            db_path=db_path,
        )

        # Combine stored history with incoming events.
        # The database already contains this batch,
        # so deduplicate using the event's full content.
        unique_events = {}

        for event in history + remote_events:
            identity = json.dumps(
                event,
                sort_keys=True,
                default=str,
            )

            unique_events[identity] = event

        detection_events = sorted(
            unique_events.values(),
            key=lambda event: parse_timestamp(
                event["timestamp"]
            ),
        )

     # Convert timestamps to datetime objects before
    # passing events to the brute-force detector.
    # Keep the original database records unchanged.

    normalized_detection_events = []

    for event in detection_events:
        normalized_event = event.copy()

        normalized_event["timestamp"] = parse_timestamp(
            event["timestamp"]
        )

        normalized_detection_events.append(
            normalized_event
        )


    alerts = detect_brute_force(
        normalized_detection_events,
        threshold=threshold,
        window_seconds=window_seconds,
    )

    # Only retain alerts whose triggering activity
    # includes events from the current batch.
    #
    # This prevents historical attacks from being
    # repeatedly reported during monitoring cycles.


    # Match alerts against genuinely new events.
    # The last triggering event must be new and must
    # belong to the same source IP and account.

    new_event_keys = set()

    for event in new_remote_events:
        new_event_keys.add((
            event.get("ip_address"),
            event.get("username"),
            parse_timestamp(event["timestamp"]),
            event.get("event_type"),
        ))

    new_alerts = []

    for alert in alerts:

        alert_type = alert.get("alert_type")

        if alert_type == "POSSIBLE_BRUTE_FORCE":
            triggering_type = "FAILED_LOGIN"

        elif alert_type == "POSSIBLE_ACCOUNT_COMPROMISE":
            triggering_type = "SUCCESS_LOGIN"

        else:
            continue

        alert_key = (
            alert.get("source_ip"),
            alert.get(
                "username",
                alert.get("target_account"),
            ),
            parse_timestamp(alert["last_attempt"]),
            triggering_type,
        )

        if alert_key in new_event_keys:
            new_alerts.append(alert)

    scored_alerts = score_alerts(new_alerts)



    saved_alerts = save_alerts(
        scored_alerts,
        db_path=db_path,
    )

    notification_results = dispatch_alerts(
    scored_alerts,
    db_path=db_path,
    minimum_severity=minimum_severity,
    email_enabled=email_enabled,
)

    return {
        "collected_events": len(events),
        "remote_events": len(remote_events),
        "local_events": len(events) - len(remote_events),
        "historical_detection_events": max(
            0,
            len(detection_events) - len(remote_events),
        ),
        "detection_events": len(detection_events),
        "saved_events": saved_events,
        "detected_alerts": len(scored_alerts),
        "saved_alerts": saved_alerts,
        "notification_previews": notification_results["previewed"],
        "notifications_sent": notification_results["sent"],
        "notification_failures": notification_results["failed"],
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

    print(
        "Normalized events:",
        results["collected_events"],
    )

    print(
        "Local/service events:",
        results["local_events"],
    )

    print(
        "Remote authentication events:",
        results["remote_events"],
    )

    print(
        "Events analyzed for detection:",
        results["detection_events"],
    )

    print(
        "Historical events included:",
        results["historical_detection_events"],
    )

    print(
        "New database events:",
        results["saved_events"],
    )

    print(
        "Detected alerts:",
        results["detected_alerts"],
    )

    print(
        "New database alerts:",
        results["saved_alerts"],
    )

    print(
        "Malformed XML events:",
        invalid,
    )

    print("=" * 55)
    print("Windows ingestion complete.")
    print("=" * 55)


if __name__ == "__main__":
    main()
