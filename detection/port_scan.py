from collections import defaultdict, deque
from datetime import timedelta


def detect_port_scans(events, threshold=10, window_seconds=60):
    """Detect possible port scanning activity."""

    if threshold < 1 or window_seconds <= 0:
        raise ValueError(
            "Threshold and detection window must be positive."
        )

    alerts = []
    connections = defaultdict(deque)
    active_alerts = set()
    window = timedelta(seconds=window_seconds)

    sorted_events = sorted(
        events, key=lambda event: event["timestamp"]
    )

    for event in sorted_events:
        key = (
            event["source_ip"],
            event["destination_ip"]
        )

        timestamp = event["timestamp"]
        port = event["destination_port"]

        attempts = connections[key]
        attempts.append((timestamp, port))

        while attempts and timestamp - attempts[0][0] > window:
            attempts.popleft()

        unique_ports = {item[1] for item in attempts}

        if len(unique_ports) < threshold:
            active_alerts.discard(key)
            continue

        if key in active_alerts:
            continue

        severity = (
            "CRITICAL" if len(unique_ports) >= 20 else "HIGH"
        )

        alerts.append({
            "alert_type": "POSSIBLE_PORT_SCAN",
            "severity": severity,
            "source_ip": key[0],
            "destination_ip": key[1],
            "unique_ports": len(unique_ports),
            "ports": sorted(unique_ports),
            "first_attempt": attempts[0][0],
            "last_attempt": timestamp,
            "time_window_seconds": window_seconds,
            "description": (
                f"{len(unique_ports)} unique destination ports "
                f"contacted within {window_seconds} seconds."
            )
        })

        active_alerts.add(key)

    return alerts


def display_network_alerts(alerts):
    """Display detected network security alerts."""

    print("\n" + "=" * 60)
    print(f"{'AllamSec Network Security Alerts':^60}")
    print("=" * 60)

    if not alerts:
        print("\nNo suspicious network scanning detected.")
        print("=" * 60)
        return

    print(f"\nTotal Network Alerts: {len(alerts)}")

    for index, alert in enumerate(alerts, start=1):
        print("\n" + "-" * 60)
        print(f"NETWORK ALERT #{index}")
        print("-" * 60)

        print(f"Alert Type:      {alert['alert_type']}")
        print(f"Severity:        {alert['severity']}")
        print(f"Source IP:       {alert['source_ip']}")
        print(f"Destination IP:  {alert['destination_ip']}")
        print(f"Unique Ports:    {alert['unique_ports']}")
        print(f"Ports:           {alert['ports']}")
        print(f"First Attempt:   {alert['first_attempt']}")
        print(f"Last Attempt:    {alert['last_attempt']}")
        print(
            f"Time Window:     "
            f"{alert['time_window_seconds']} seconds"
        )
        print(f"\nDescription: {alert['description']}")

    print("\n" + "=" * 60)