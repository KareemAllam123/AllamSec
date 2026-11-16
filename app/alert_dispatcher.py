
"""Persistent security alert notifications for AllamSec."""

import logging

from database.db_manager import (
    DEFAULT_DB_PATH,
    create_hash,
    database_connection,
    normalize_value,
)

from app.notification_manager import (
    send_email_notification,
    should_notify,
)

logger = logging.getLogger("AllamSec.notifications")

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_STALE_SECONDS = 300


def initialize_notifications(db_path=DEFAULT_DB_PATH):
    """Create persistent notification history."""

    with database_connection(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'PREVIEW',
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (alert_id) REFERENCES security_alerts(id)
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_notifications_status
            ON alert_notifications(status, updated_at)
        """)


def get_alert_hash(alert):
    """Match the alert identity used by save_alerts."""

    normalized = normalize_value(alert)

    identity = {
        key: value
        for key, value in normalized.items()
        if key not in (
            "risk_score",
            "severity",
            "description",
        )
    }

    return create_hash(identity)


def recover_stale_notifications(
    db_path=DEFAULT_DB_PATH,
    stale_seconds=DEFAULT_STALE_SECONDS,
):
    """Move interrupted deliveries to REVIEW.

    REVIEW notifications must not be automatically resent
    because SMTP delivery might already have succeeded.
    """

    if (
        not isinstance(stale_seconds, int)
        or stale_seconds < 1
    ):
        raise ValueError(
            "stale_seconds must be a positive integer."
        )

    initialize_notifications(db_path)

    modifier = f"-{stale_seconds} seconds"

    with database_connection(db_path) as connection:
        recovered = connection.execute("""
            UPDATE alert_notifications
            SET status = 'REVIEW',
                last_error =
                    'Delivery interrupted or timed out; '
                    || 'verify whether email was received.',
                updated_at = CURRENT_TIMESTAMP
            WHERE status = 'SENDING'
              AND updated_at <= datetime('now', ?)
        """, (modifier,)).rowcount

    if recovered:
        logger.warning(
            "%s interrupted notification(s) require review.",
            recovered,
        )

    return recovered


def dispatch_alerts(
    alerts,
    db_path=DEFAULT_DB_PATH,
    minimum_severity="HIGH",
    email_enabled=False,
    max_attempts=DEFAULT_MAX_ATTEMPTS,
):
    """Persist eligible notifications and optionally send email.

    Notifications in SENT or REVIEW are never automatically
    resent. Failed notifications can be retried up to the
    configured attempt limit.
    """

    if (
        not isinstance(max_attempts, int)
        or max_attempts < 1
    ):
        raise ValueError(
            "max_attempts must be a positive integer."
        )

    initialize_notifications(db_path)

    recover_stale_notifications(db_path)

    summary = {
        "eligible": 0,
        "previewed": 0,
        "sent": 0,
        "failed": 0,
        "skipped": 0,
    }

    for alert in alerts:
        if not should_notify(alert, minimum_severity):
            summary["skipped"] += 1
            continue

        alert_hash = get_alert_hash(alert)

        with database_connection(db_path) as connection:
            stored = connection.execute("""
                SELECT id
                FROM security_alerts
                WHERE alert_hash = ?
            """, (alert_hash,)).fetchone()

            if stored is None:
                raise RuntimeError(
                    "Cannot notify about an alert that was not saved."
                )

            alert_id = stored["id"]

            connection.execute("""
                INSERT OR IGNORE INTO alert_notifications (
                    alert_id,
                    status
                )
                VALUES (?, 'PREVIEW')
            """, (alert_id,))

            notification = connection.execute("""
                SELECT status
                FROM alert_notifications
                WHERE alert_id = ?
            """, (alert_id,)).fetchone()

        summary["eligible"] += 1

        if not email_enabled:
            if notification["status"] == "PREVIEW":
                summary["previewed"] += 1
            else:
                summary["skipped"] += 1
            continue

        # Atomically claim a notification.
        # REVIEW and SENT are intentionally excluded.
        with database_connection(db_path) as connection:
            claimed = connection.execute("""
                UPDATE alert_notifications
                SET status = 'SENDING',
                    attempts = attempts + 1,
                    last_error = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE alert_id = ?
                  AND status IN ('PREVIEW', 'FAILED')
                  AND attempts < ?
            """, (
                alert_id,
                max_attempts,
            )).rowcount

        if not claimed:
            summary["skipped"] += 1
            continue

        try:
            send_email_notification(alert)

        except Exception as exc:
            with database_connection(db_path) as connection:
                connection.execute("""
                    UPDATE alert_notifications
                    SET status = 'FAILED',
                        last_error = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE alert_id = ?
                      AND status = 'SENDING'
                """, (
                    str(exc)[:500],
                    alert_id,
                ))

            summary["failed"] += 1

            logger.exception(
                "Notification delivery failed for alert %s",
                alert_id,
            )

        else:
            with database_connection(db_path) as connection:
                connection.execute("""
                    UPDATE alert_notifications
                    SET status = 'SENT',
                        last_error = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE alert_id = ?
                      AND status = 'SENDING'
                """, (alert_id,))

            summary["sent"] += 1

    return summary


def get_notification_history(
    db_path=DEFAULT_DB_PATH,
    limit=50,
):
    """Return recent notifications and their alert details."""

    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError(
            "limit must be between 1 and 500."
        )

    initialize_notifications(db_path)

    with database_connection(db_path) as connection:
        rows = connection.execute("""
            SELECT
                n.id,
                n.alert_id,
                n.status,
                n.attempts,
                n.last_error,
                n.created_at,
                a.alert_type,
                a.severity,
                a.risk_score,
                a.source_ip,
                a.username
            FROM alert_notifications AS n
            JOIN security_alerts AS a
              ON a.id = n.alert_id
            ORDER BY n.id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_notification_summary(db_path=DEFAULT_DB_PATH):
    """Return notification counts by delivery status."""

    initialize_notifications(db_path)

    summary = {
        "total": 0,
        "preview": 0,
        "sending": 0,
        "sent": 0,
        "failed": 0,
        "review": 0,
    }

    with database_connection(db_path) as connection:
        rows = connection.execute("""
            SELECT status, COUNT(*) AS total
            FROM alert_notifications
            GROUP BY status
        """).fetchall()

    for row in rows:
        status = row["status"].lower()

        if status in summary:
            summary[status] = row["total"]

        summary["total"] += row["total"]

    return summary
