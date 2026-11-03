"""SQLite database management for AllamSec."""

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "database" / "allamsec.db"


def normalize_value(value):
    """Convert Python values into JSON-compatible values."""

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            key: normalize_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [normalize_value(item) for item in value]

    return value


def create_hash(data):
    """Create a consistent SHA-256 hash for a record."""

    normalized = normalize_value(data)

    serialized = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def get_connection(db_path=DEFAULT_DB_PATH):
    """Open a connection to the SQLite database."""

    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")

    return connection


@contextmanager
def database_connection(db_path=DEFAULT_DB_PATH):
    """Manage transactions and always close the connection."""

    connection = get_connection(db_path)

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database(db_path=DEFAULT_DB_PATH):
    """Create the required database tables and indexes."""

    with database_connection(db_path) as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_hash TEXT NOT NULL UNIQUE,
                event_source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                destination_port INTEGER,
                event_data TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_hash TEXT NOT NULL UNIQUE,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL
                    CHECK (risk_score BETWEEN 0 AND 100),
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                description TEXT,
                first_attempt TEXT,
                last_attempt TEXT,
                alert_data TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON security_events(event_timestamp);

            CREATE INDEX IF NOT EXISTS idx_events_source
                ON security_events(event_source);

            CREATE INDEX IF NOT EXISTS idx_alerts_risk
                ON security_alerts(risk_score DESC);

            CREATE INDEX IF NOT EXISTS idx_alerts_type
                ON security_alerts(alert_type);
        """)


def save_events(events, event_source, db_path=DEFAULT_DB_PATH):
    """Save security events while preventing duplicate records."""

    if event_source not in ("authentication", "network"):
        raise ValueError("Unsupported event source.")

    saved = 0

    with database_connection(db_path) as connection:
        for event in events:
            normalized = normalize_value(event)

            if event_source == "authentication":
                event_type = event["event_type"]
                source_ip = event["ip_address"]
                destination_ip = None
                username = event["username"]
                destination_port = None

            else:
                event_type = event["status"]
                source_ip = event["source_ip"]
                destination_ip = event["destination_ip"]
                username = None
                destination_port = event["destination_port"]

            event_hash = create_hash({
                "source": event_source,
                "event": normalized,
            })

            cursor = connection.execute("""
                INSERT OR IGNORE INTO security_events (
                    event_hash,
                    event_source,
                    event_type,
                    event_timestamp,
                    source_ip,
                    destination_ip,
                    username,
                    destination_port,
                    event_data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_hash,
                event_source,
                event_type,
                normalized["timestamp"],
                source_ip,
                destination_ip,
                username,
                destination_port,
                json.dumps(normalized, sort_keys=True),
            ))

            saved += cursor.rowcount

    return saved


def save_alerts(alerts, db_path=DEFAULT_DB_PATH):
    """Save new alerts and update previously stored alerts."""

    inserted = 0

    with database_connection(db_path) as connection:
        for alert in alerts:
            normalized = normalize_value(alert)

            # Exclude calculated fields from the alert identity.
            # This allows risk scores to change without creating
            # duplicate alerts.
            identity = {
                key: value
                for key, value in normalized.items()
                if key not in (
                    "risk_score",
                    "severity",
                    "description",
                )
            }

            alert_hash = create_hash(identity)

            existing = connection.execute("""
                SELECT id
                FROM security_alerts
                WHERE alert_hash = ?
            """, (alert_hash,)).fetchone()

            connection.execute("""
                INSERT INTO security_alerts (
                    alert_hash,
                    alert_type,
                    severity,
                    risk_score,
                    source_ip,
                    destination_ip,
                    username,
                    description,
                    first_attempt,
                    last_attempt,
                    alert_data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_hash) DO UPDATE SET
                    severity = excluded.severity,
                    risk_score = excluded.risk_score,
                    description = excluded.description,
                    alert_data = excluded.alert_data
            """, (
                alert_hash,
                alert["alert_type"],
                alert["severity"],
                alert["risk_score"],
                alert.get("source_ip"),
                alert.get("destination_ip"),
                alert.get(
                    "username",
                    alert.get("target_account")
                ),
                alert.get("description"),
                normalized.get("first_attempt"),
                normalized.get("last_attempt"),
                json.dumps(normalized, sort_keys=True),
            ))

            if existing is None:
                inserted += 1

    return inserted


def get_event_count(db_path=DEFAULT_DB_PATH):
    """Return the total number of stored security events."""

    with database_connection(db_path) as connection:
        row = connection.execute("""
            SELECT COUNT(*) AS total
            FROM security_events
        """).fetchone()

    return row["total"]


def get_alert_count(db_path=DEFAULT_DB_PATH):
    """Return the total number of stored security alerts."""

    with database_connection(db_path) as connection:
        row = connection.execute("""
            SELECT COUNT(*) AS total
            FROM security_alerts
        """).fetchone()

    return row["total"]


def get_recent_alerts(limit=10, db_path=DEFAULT_DB_PATH):
    """Retrieve stored alerts ordered by risk score."""

    if not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("Limit must be between 1 and 1000.")

    with database_connection(db_path) as connection:
        rows = connection.execute("""
            SELECT *
            FROM security_alerts
            ORDER BY risk_score DESC, id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_database_summary(db_path=DEFAULT_DB_PATH):
    """Return database statistics for security monitoring."""

    with database_connection(db_path) as connection:

        events = connection.execute("""
            SELECT COUNT(*) AS total
            FROM security_events
        """).fetchone()["total"]

        alerts = connection.execute("""
            SELECT COUNT(*) AS total
            FROM security_alerts
        """).fetchone()["total"]

        critical = connection.execute("""
            SELECT COUNT(*) AS total
            FROM security_alerts
            WHERE severity = 'CRITICAL'
        """).fetchone()["total"]

        highest = connection.execute("""
            SELECT MAX(risk_score) AS highest
            FROM security_alerts
        """).fetchone()["highest"]

    return {
        "total_events": events,
        "total_alerts": alerts,
        "critical_alerts": critical,
        "highest_risk_score": highest,
    }


def display_database_summary(db_path=DEFAULT_DB_PATH):
    """Display a summary of stored security data."""

    summary = get_database_summary(db_path)

    print("\n" + "=" * 60)
    print(f"{'AllamSec Database Summary':^60}")
    print("=" * 60)

    print(
        f"Stored Security Events: "
        f"{summary['total_events']}"
    )

    print(
        f"Stored Security Alerts: "
        f"{summary['total_alerts']}"
    )

    print(
        f"Critical Alerts:        "
        f"{summary['critical_alerts']}"
    )

    highest = summary["highest_risk_score"]

    highest_display = (
        f"{highest}/100"
        if highest is not None
        else "N/A"
    )

    print(f"Highest Stored Risk:    {highest_display}")

    print("=" * 60)