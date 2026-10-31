from collections import defaultdict, deque
from datetime import timedelta


def detect_brute_force(events, threshold=5, window_seconds=60):
    """
    Detect possible brute-force attacks and successful logins
    following repeated failed authentication attempts.

    A brute-force alert is generated when an IP address makes
    a specified number of failed login attempts against the
    same account within the detection window.

    A possible account compromise alert is generated when
    a successful login occurs shortly after a brute-force alert.

    Returns:
        list: Security alerts detected in the authentication logs.
    """

    # Validate detection settings
    if threshold < 1 or window_seconds <= 0:
        raise ValueError(
            "Threshold and detection window must be positive."
        )

    alerts = []

    # Store recent failed login timestamps for each IP/account pair
    failed_attempts = defaultdict(deque)

    # Track active brute-force detections
    active_brute_force = {}

    # Process events chronologically
    sorted_events = sorted(
        events,
        key=lambda event: event["timestamp"]
    )

    time_window = timedelta(seconds=window_seconds)

    for event in sorted_events:

        ip_address = event["ip_address"]
        username = event["username"]
        timestamp = event["timestamp"]
        event_type = event["event_type"]

        # Identify a unique IP address and account combination
        key = (ip_address, username)

        # Remove expired brute-force detection tracking
        if key in active_brute_force:

            last_alert_time = active_brute_force[key]["timestamp"]

            if timestamp - last_alert_time > time_window:
                del active_brute_force[key]

        # ----------------------------------------
        # Detect repeated failed login attempts
        # ----------------------------------------

        if event_type == "FAILED_LOGIN":

            attempts = failed_attempts[key]

            # Add the current failed login timestamp
            attempts.append(timestamp)

            # Remove attempts outside the detection window
            while attempts and timestamp - attempts[0] > time_window:
                attempts.popleft()

            # Generate an alert when the threshold is reached
            # and there is no active alert for this IP/account.
            if (
                len(attempts) >= threshold
                and key not in active_brute_force
            ):

                alert = {
                    "alert_type": "POSSIBLE_BRUTE_FORCE",
                    "severity": "HIGH",
                    "source_ip": ip_address,
                    "target_account": username,
                    "failed_attempts": len(attempts),
                    "first_attempt": attempts[0],
                    "last_attempt": attempts[-1],
                    "time_window_seconds": window_seconds,
                    "description": (
                        f"{len(attempts)} failed login attempts "
                        f"detected within {window_seconds} seconds."
                    )
                }

                alerts.append(alert)

                # Save information about the detected attack
                active_brute_force[key] = {
                    "timestamp": timestamp,
                    "first_attempt": attempts[0],
                    "failed_attempts": len(attempts)
                }

        # ----------------------------------------
        # Detect successful login after brute force
        # ----------------------------------------

        elif event_type == "SUCCESS_LOGIN":

            if key in active_brute_force:

                attack = active_brute_force[key]

                last_alert_time = attack["timestamp"]

                time_difference = (
                    timestamp - last_alert_time
                ).total_seconds()

                if 0 <= time_difference <= window_seconds:

                    alert = {
                        "alert_type": "POSSIBLE_ACCOUNT_COMPROMISE",
                        "severity": "CRITICAL",
                        "source_ip": ip_address,
                        "target_account": username,
                        "failed_attempts": attack["failed_attempts"],
                        "first_attempt": attack["first_attempt"],
                        "last_attempt": timestamp,
                        "time_window_seconds": window_seconds,
                        "description": (
                            "A successful login occurred "
                            "shortly after multiple failed "
                            "authentication attempts."
                        )
                    }

                    alerts.append(alert)

                # Prevent duplicate compromise alerts
                del active_brute_force[key]

            # Reset failed login history after a successful login
            failed_attempts.pop(key, None)

    return alerts


def display_security_alerts(alerts):
    """
    Display AllamSec security alerts in the terminal.
    """

    print("\n" + "=" * 60)
    print(f"{'AllamSec Security Alerts':^60}")
    print("=" * 60)

    if not alerts:
        print("\nNo suspicious authentication patterns detected.")
        print("=" * 60)
        return

    print(f"\nTotal Alerts Generated: {len(alerts)}")

    for index, alert in enumerate(alerts, start=1):

        print("\n" + "-" * 60)
        print(f"ALERT #{index}")
        print("-" * 60)

        print(f"Alert Type:      {alert['alert_type']}")
        print(f"Severity:        {alert['severity']}")
        print(f"Source IP:       {alert['source_ip']}")
        print(f"Target Account:  {alert['target_account']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")
        print(f"First Attempt:   {alert['first_attempt']}")
        print(f"Last Attempt:    {alert['last_attempt']}")
        print(f"Time Window:     {alert['time_window_seconds']} seconds")

        print(f"\nDescription: {alert['description']}")

    print("\n" + "=" * 60)