from pathlib import Path
from datetime import datetime
import ipaddress


def parse_log_line(line):
    """
    Parse a single authentication log entry.

    Expected format:
    YYYY-MM-DD HH:MM:SS EVENT_TYPE user=USERNAME ip=IP_ADDRESS

    Supported event types:
    - FAILED_LOGIN
    - SUCCESS_LOGIN

    Returns:
        dict: Parsed authentication event.
        None: If the log entry is invalid.
    """

    # Remove whitespace and split the log into components
    parts = line.strip().split()

    # Every valid log entry must contain exactly 5 components
    if len(parts) != 5:
        return None

    date, time, event_type, user_field, ip_field = parts

    # Validate the authentication event type
    valid_event_types = {"FAILED_LOGIN", "SUCCESS_LOGIN"}

    if event_type not in valid_event_types:
        return None

    # Validate the username and IP address fields
    if not user_field.startswith("user="):
        return None

    if not ip_field.startswith("ip="):
        return None

    # Extract the username and IP address
    username = user_field.split("=", 1)[1]
    ip_address = ip_field.split("=", 1)[1]

    # Reject missing values
    if not username or not ip_address:
        return None

    try:
        # Convert the timestamp into a datetime object
        timestamp = datetime.strptime(
            f"{date} {time}",
            "%Y-%m-%d %H:%M:%S"
        )

        # Validate the IP address
        ipaddress.ip_address(ip_address)

    except ValueError:
        # Reject invalid timestamps or IP addresses
        return None

    # Return the structured authentication event
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username,
        "ip_address": ip_address
    }


def read_log_file(file_path):
    """
    Read and parse authentication events from a log file.

    Args:
        file_path: Path to the authentication log.

    Returns:
        tuple:
            events: List of valid authentication events.
            invalid_lines: Number of malformed log entries.
    """

    events = []
    invalid_lines = 0

    path = Path(file_path)

    # Verify that the log file exists and is a regular file
    if not path.is_file():
        print(f"Error: Log file not found: {path}")
        return events, invalid_lines

    # Open the authentication log
    with path.open("r", encoding="utf-8") as file:

        # Process each log entry
        for line_number, line in enumerate(file, start=1):

            # Ignore empty lines
            if not line.strip():
                continue

            # Parse the current log entry
            event = parse_log_line(line)

            if event is not None:
                events.append(event)

            else:
                invalid_lines += 1

                print(
                    f"Warning: Invalid log entry at line {line_number}"
                )

    return events, invalid_lines