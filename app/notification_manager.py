
"""Notification management for AllamSec security alerts."""

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage


logger = logging.getLogger("AllamSec.notifications")

SEVERITY_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def should_notify(alert, minimum_severity="HIGH"):
    """Determine whether an alert meets the notification threshold."""

    severity = str(
        alert.get("severity", "")
    ).upper()

    minimum_severity = minimum_severity.upper()

    if minimum_severity not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid minimum severity: {minimum_severity}"
        )

    return (
        SEVERITY_LEVELS.get(severity, 0)
        >= SEVERITY_LEVELS[minimum_severity]
    )


def format_alert_message(alert):
    """Create a readable security notification."""

    return (
        "ALLAMSEC SECURITY ALERT\n"
        "=======================\n"
        f"Type: {alert.get('alert_type', 'Unknown')}\n"
        f"Severity: {alert.get('severity', 'Unknown')}\n"
        f"Source IP: {alert.get('source_ip', 'Unknown')}\n"
        f"Username: {alert.get('username', 'Unknown')}\n"
        f"Risk Score: {alert.get('risk_score', 'N/A')}\n"
        "\n"
        "Review the alert in your AllamSec dashboard.\n"
    )


def send_email_notification(alert):
    """Send a security alert using SMTP configuration."""

    smtp_host = os.getenv("ALLAMSEC_SMTP_HOST")
    smtp_port = int(os.getenv("ALLAMSEC_SMTP_PORT", "465"))
    smtp_user = os.getenv("ALLAMSEC_SMTP_USER")
    smtp_password = os.getenv("ALLAMSEC_SMTP_PASSWORD")
    recipient = os.getenv("ALLAMSEC_ALERT_EMAIL")

    if not all(
        [
            smtp_host,
            smtp_user,
            smtp_password,
            recipient,
        ]
    ):
        raise RuntimeError(
            "Email notification configuration is incomplete."
        )

    message = EmailMessage()

    message["Subject"] = (
        "[AllamSec] "
        f"{alert.get('severity', 'UNKNOWN')} Security Alert"
    )
    message["From"] = smtp_user
    message["To"] = recipient

    message.set_content(
        format_alert_message(alert)
    )

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        smtp_host,
        smtp_port,
        context=context,
        timeout=15,
    ) as server:
        server.login(smtp_user, smtp_password)
        server.send_message(message)

    logger.info(
        "Security notification sent successfully."
    )

    return True


def notify_alerts(
    alerts,
    minimum_severity="HIGH",
    email_enabled=False,
):
    """Process notifications for eligible alerts."""

    notified = 0
    eligible = 0
    failed = 0

    for alert in alerts:
        if not should_notify(alert, minimum_severity):
            continue

        eligible += 1

        if not email_enabled:
            logger.info(
                "Notification preview:\n%s",
                format_alert_message(alert),
            )
            continue

        try:
            send_email_notification(alert)
            notified += 1

        except (RuntimeError, OSError, ValueError, smtplib.SMTPException):
            failed += 1
            logger.exception(
                "Unable to deliver security notification."
            )

    return {
        "eligible_alerts": eligible,
        "sent_notifications": notified,
        "failed_notifications": failed,
    }
