import ipaddress
from datetime import datetime
from pathlib import Path


VALID_STATUSES = {"ALLOWED", "BLOCKED"}


def parse_network_line(line):
    """Parse a network connection log entry."""

    parts = line.strip().split()

    if len(parts) != 6:
        return None

    date, time, status, src_field, dst_field, port_field = parts

    if status not in VALID_STATUSES:
        return None

    try:
        timestamp = datetime.strptime(
            f"{date} {time}", "%Y-%m-%d %H:%M:%S"
        )

        if not src_field.startswith("src="):
            return None

        if not dst_field.startswith("dst="):
            return None

        if not port_field.startswith("port="):
            return None

        source_ip = src_field.split("=", 1)[1]
        destination_ip = dst_field.split("=", 1)[1]
        port = int(port_field.split("=", 1)[1])

        ipaddress.ip_address(source_ip)
        ipaddress.ip_address(destination_ip)

        if not 1 <= port <= 65535:
            return None

        return {
            "timestamp": timestamp,
            "status": status,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": port,
        }

    except (ValueError, TypeError):
        return None


def read_network_log(file_path):
    """Read a network log and count malformed entries."""

    path = Path(file_path)
    events = []
    invalid_lines = 0

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            event = parse_network_line(line)

            if event is None:
                invalid_lines += 1
                print(
                    f"Warning: Invalid network log at line "
                    f"{line_number}"
                )
            else:
                events.append(event)

    return events, invalid_lines