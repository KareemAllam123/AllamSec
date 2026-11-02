"""Centralized risk scoring for AllamSec security alerts."""

BASE_SCORES = {
    "POSSIBLE_BRUTE_FORCE": 50,
    "POSSIBLE_PORT_SCAN": 50,
    "POSSIBLE_ACCOUNT_COMPROMISE": 85,
}


def classify_severity(score):
    """Convert a numerical risk score into a severity level."""

    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100.")

    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def calculate_risk_score(alert):
    """Calculate a risk score from a detected security alert."""

    alert_type = alert.get("alert_type")

    if alert_type not in BASE_SCORES:
        raise ValueError(f"Unsupported alert type: {alert_type}")

    score = BASE_SCORES[alert_type]

    if alert_type == "POSSIBLE_BRUTE_FORCE":
        attempts = max(0, int(alert.get("failed_attempts", 0)))
        score += min(25, attempts * 3)

    elif alert_type == "POSSIBLE_PORT_SCAN":
        ports = max(0, int(alert.get("unique_ports", 0)))
        score += min(30, ports * 2)

    elif alert_type == "POSSIBLE_ACCOUNT_COMPROMISE":
        attempts = max(0, int(alert.get("failed_attempts", 0)))
        score += min(15, attempts * 2)

    return min(100, score)


def score_alert(alert):
    """Return an enriched alert without changing the original."""

    scored_alert = alert.copy()
    risk_score = calculate_risk_score(alert)

    scored_alert["risk_score"] = risk_score
    scored_alert["severity"] = classify_severity(risk_score)

    return scored_alert


def score_alerts(alerts):
    """Score and prioritize alerts from highest to lowest risk."""

    scored_alerts = [score_alert(alert) for alert in alerts]

    return sorted(
        scored_alerts,
        key=lambda alert: alert["risk_score"],
        reverse=True,
    )


def display_risk_report(alerts):
    """Display a prioritized security risk report."""

    print("\n" + "=" * 60)
    print(f"{'AllamSec Threat Risk Assessment':^60}")
    print("=" * 60)

    if not alerts:
        print("\nNo security alerts to assess.")
        print("=" * 60)
        return

    prioritized_alerts = score_alerts(alerts)

    print(f"\nTotal Threats Assessed: {len(prioritized_alerts)}")

    for index, alert in enumerate(prioritized_alerts, start=1):
        print("\n" + "-" * 60)
        print(f"THREAT #{index}")
        print("-" * 60)

        print(f"Alert Type:  {alert['alert_type']}")
        print(f"Severity:    {alert['severity']}")
        print(f"Risk Score:  {alert['risk_score']}/100")
        print(f"Source IP:   {alert.get('source_ip', 'Unknown')}")

        if "username" in alert:
            print(f"Username:    {alert['username']}")

        if "destination_ip" in alert:
            print(f"Destination: {alert['destination_ip']}")

        print(f"Description: {alert.get('description', 'N/A')}")

    print("\n" + "=" * 60)