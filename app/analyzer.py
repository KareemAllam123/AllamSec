from collections import defaultdict


def analyze_authentication_events(events):
    """
    Analyze authentication events and calculate security statistics.

    Returns:
        dict: Authentication statistics, including login counts,
              failed-login percentage, and IP address activity.
    """

    # Initialize authentication counters
    total_events = len(events)
    failed_logins = 0
    successful_logins = 0

    # Store authentication statistics for each IP address
    ip_statistics = defaultdict(
        lambda: {
            "failed": 0,
            "successful": 0,
            "total": 0
        }
    )

    # Process each authentication event
    for event in events:

        ip_address = event["ip_address"]
        event_type = event["event_type"]

        if event_type == "FAILED_LOGIN":

            failed_logins += 1
            ip_statistics[ip_address]["failed"] += 1
            ip_statistics[ip_address]["total"] += 1

        elif event_type == "SUCCESS_LOGIN":

            successful_logins += 1
            ip_statistics[ip_address]["successful"] += 1
            ip_statistics[ip_address]["total"] += 1

    # Calculate the failed-login percentage
    failed_login_rate = (
        (failed_logins / total_events) * 100
        if total_events > 0 else 0.0
    )

    # Return the authentication statistics
    return {
        "total_events": total_events,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "failed_login_rate": failed_login_rate,
        "unique_ips": len(ip_statistics),
        "ip_statistics": dict(ip_statistics)
    }


def display_report(statistics, invalid_lines):
    """
    Display a formatted AllamSec authentication analysis report.
    """

    print("\n" + "=" * 55)
    print(f"{'AllamSec Log Analyzer':^55}")
    print("=" * 55)

    # Authentication summary
    print("\nAUTHENTICATION SUMMARY")
    print("-" * 55)

    print(f"Total Events:       {statistics['total_events']}")
    print(f"Failed Logins:      {statistics['failed_logins']}")
    print(f"Successful Logins:  {statistics['successful_logins']}")
    print(f"Failed Login Rate:  {statistics['failed_login_rate']:.2f}%")
    print(f"Unique IPs:         {statistics['unique_ips']}")
    print(f"Invalid Log Lines:  {invalid_lines}")

    # IP address activity
    print("\nIP ADDRESS ACTIVITY")
    print("-" * 55)

    if not statistics["ip_statistics"]:
        print("No authentication activity detected.")

    else:
        for ip_address, data in sorted(
            statistics["ip_statistics"].items()
        ):

            print(f"\nIP Address: {ip_address}")
            print(f"  Total Events:      {data['total']}")
            print(f"  Failed Logins:     {data['failed']}")
            print(f"  Successful Logins: {data['successful']}")

    print("\n" + "=" * 55)
    print(f"{'Analysis Complete':^55}")
    print("=" * 55)