
"""Linux SSH authentication log collector for AllamSec."""

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path


MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3,
    "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9,
    "Oct": 10, "Nov": 11, "Dec": 12,
}

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

SSH_LOGIN_PATTERN = re.compile(
    r"^(?P<result>Failed|Accepted)\s+"
    r"(?P<method>\S+)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+"
    r"(?P<port>\d+)",
    re.IGNORECASE,
)


def parse_linux_auth_line(line, year=None):
    """Parse one Linux sshd authentication log entry.

    Returns a normalized event or None for unsupported lines.
    """

    if year is None:
        year = datetime.now(timezone.utc).year

    match = SYSLOG_PATTERN.match(line.strip())

    if not match:
        return None

    message = match.group("message")
    login = SSH_LOGIN_PATTERN.match(message)

    if not login:
        return None

    month = MONTHS.get(match.group("month"))

    if month is None:
        return None

    try:
        timestamp = datetime.strptime(
            f"{year}-{month:02d}-{int(match.group('day')):02d} "
            f"{match.group('time')}",
            "%Y-%m-%d %H:%M:%S",
        )
    except ValueError:
        return None

    result = login.group("result").lower()

    return {
        "timestamp": timestamp,
        "event_type": (
            "FAILED_LOGIN"
            if result == "failed"
            else "SUCCESS_LOGIN"
        ),
        "username": login.group("username"),
        "ip_address": login.group("ip"),
        "source_ip": login.group("ip"),
        "destination_port": 22,
        "source_port": int(login.group("port")),
        "computer": match.group("host"),
        "process_id": match.group("pid"),
        "authentication_method": login.group("method"),
        "invalid_user": bool(login.group("invalid")),
        "event_origin": "linux_ssh",
        "raw_log": line.strip(),
    }


def read_linux_auth_file(file_path, year=None):
    """Read and normalize supported SSH login events.

    Returns (events, invalid_lines).

    Non-SSH and unrelated system log lines are ignored.
    Malformed SSH authentication lines are counted.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Linux authentication log not found: {path}"
        )

    events = []
    invalid_lines = 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:
        for line in file:
            stripped = line.strip()

            if not stripped:
                continue

            event = parse_linux_auth_line(
                stripped,
                year=year,
            )

            if event is not None:
                events.append(event)
            elif "sshd" in stripped.lower() and (
                "failed password" in stripped.lower()
                or "accepted password" in stripped.lower()
                or "accepted publickey" in stripped.lower()
                or "failed publickey" in stripped.lower()
            ):
                invalid_lines += 1

    return events, invalid_lines


def main():
    parser = argparse.ArgumentParser(
        description="Parse Linux SSH authentication logs."
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Path to auth.log or secure.",
    )

    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year for syslog timestamps.",
    )

    args = parser.parse_args()

    events, invalid = read_linux_auth_file(
        args.file,
        year=args.year,
    )

    print("=" * 55)
    print("ALLAMSEC - LINUX SSH LOG COLLECTOR")
    print("=" * 55)
    print(f"Normalized events: {len(events)}")
    print(f"Malformed SSH events: {invalid}")

    for event in events[:10]:
        print(
            f"{event['timestamp']} | "
            f"{event['event_type']} | "
            f"{event['username']} | "
            f"{event['ip_address']}"
        )

    print("=" * 55)


if __name__ == "__main__":
    main()
