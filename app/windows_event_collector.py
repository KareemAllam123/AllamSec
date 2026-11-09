
"""Collect Windows Security authentication events for AllamSec."""

import ipaddress
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


EVENT_IDS = {
    4624: "SUCCESS_LOGIN",
    4625: "FAILED_LOGIN",
}

LOGON_TYPES = {
    0: "UNKNOWN",
    2: "INTERACTIVE",
    3: "NETWORK",
    4: "BATCH",
    5: "SERVICE",
    7: "UNLOCK",
    8: "NETWORK_CLEARTEXT",
    9: "NEW_CREDENTIALS",
    10: "REMOTE_INTERACTIVE",
    11: "CACHED_INTERACTIVE",
}

REMOTE_LOGON_TYPES = {3, 8, 10}

EVENT_PATTERN = re.compile(
    r"<(?:\w+:)?Event(?:\s[^>]*)?>.*?</(?:\w+:)?Event>",
    re.DOTALL,
)


def local_name(tag):
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def is_remote_address(address):
    """Check whether an IP can identify a non-loopback source."""
    if not address or address == "-":
        return False

    try:
        ip = ipaddress.ip_address(address)
        return not (ip.is_loopback or ip.is_unspecified)
    except ValueError:
        return False


def parse_windows_event(xml_text):
    """Normalize one Windows authentication event."""

    root = ET.fromstring(xml_text)

    if local_name(root.tag) != "Event":
        return None

    system = next(
        (item for item in root
         if local_name(item.tag) == "System"),
        None,
    )

    event_data = next(
        (item for item in root
         if local_name(item.tag) == "EventData"),
        None,
    )

    if system is None or event_data is None:
        return None

    event_id = None
    timestamp_text = None
    record_id = None
    computer = None

    for element in system:
        name = local_name(element.tag)

        if name == "EventID":
            event_id = int(element.text)
        elif name == "TimeCreated":
            timestamp_text = element.get("SystemTime")
        elif name == "EventRecordID":
            record_id = element.text
        elif name == "Computer":
            computer = element.text

    if event_id not in EVENT_IDS or not timestamp_text:
        return None

    fields = {}

    for element in event_data:
        if local_name(element.tag) == "Data":
            name = element.get("Name")
            if name:
                fields[name] = element.text or ""

    try:
        logon_type = int(fields.get("LogonType", "0"))
    except ValueError:
        logon_type = 0

    try:
        timestamp = datetime.fromisoformat(
            timestamp_text.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        timestamp = timestamp.astimezone(
            timezone.utc
        ).replace(tzinfo=None)

    except ValueError:
        return None

    username = (
        fields.get("TargetUserName", "").strip()
        or "UNKNOWN"
    )

    source_ip = (
        fields.get("IpAddress", "").strip()
        or "-"
    )

    remote_source = (
        logon_type in REMOTE_LOGON_TYPES
        and is_remote_address(source_ip)
    )

    return {
        "timestamp": timestamp,
        "event_type": EVENT_IDS[event_id],
        "username": username,
        "ip_address": source_ip,
        "windows_event_id": event_id,
        "windows_record_id": record_id,
        "computer": computer,
        "logon_type": logon_type,
        "logon_type_name": LOGON_TYPES.get(
            logon_type, "OTHER"
        ),
        "is_remote_authentication": remote_source,
        "authentication_status": fields.get("Status"),
        "authentication_substatus": fields.get("SubStatus"),
        "event_origin": "windows_security",
    }


def parse_windows_xml(xml_text):
    """Parse XML containing one or more Windows events."""

    events = []
    invalid_count = 0

    matches = EVENT_PATTERN.findall(xml_text)

    for match in matches:
        try:
            event = parse_windows_event(match)
        except (ET.ParseError, ValueError, TypeError):
            invalid_count += 1
            continue

        if event is not None:
            events.append(event)

    if not matches and xml_text.strip():
        invalid_count = 1

    events.sort(key=lambda item: item["timestamp"])

    return events, invalid_count


def read_windows_xml_file(file_path):
    """Import Windows event XML from a saved file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Windows event file not found: {path}"
        )

    return parse_windows_xml(
        path.read_text(encoding="utf-8-sig")
    )


def collect_windows_events(max_events=500):
    """Read existing Windows Security events with wevtutil."""

    if not 1 <= max_events <= 10000:
        raise ValueError(
            "max_events must be between 1 and 10000."
        )

    query = "*[System[(EventID=4624 or EventID=4625)]]"

    command = [
        "wevtutil",
        "qe",
        "Security",
        f"/q:{query}",
        "/rd:true",
        f"/c:{max_events}",
        "/f:xml",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Windows Event Log utility was not found."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Windows event collection timed out."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            "Unable to read Windows Security events. "
            + result.stderr.strip()[:500]
        )

    return parse_windows_xml(result.stdout)


def collect_windows_events_since(
    last_record_id=None,
    batch_size=500,
):
    """Collect one ascending batch of Windows authentication events.

    Uses EventRecordID to request only records newer than the
    checkpoint. Returns (events, invalid_count).
    """

    if last_record_id is not None:
        if (
            type(last_record_id) is not int
            or last_record_id < 0
        ):
            raise ValueError("Invalid last_record_id.")

    if not 1 <= batch_size <= 10000:
        raise ValueError(
            "batch_size must be between 1 and 10000."
        )

    condition = "(EventID=4624 or EventID=4625)"

    if last_record_id is not None:
        condition += (
            f" and EventRecordID>{last_record_id}"
        )

    query = f"*[System[{condition}]]"

    command = [
        "wevtutil",
        "qe",
        "Security",
        f"/q:{query}",
        "/rd:false",
        f"/c:{batch_size}",
        "/f:xml",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )

    except FileNotFoundError as exc:
        raise RuntimeError(
            "Windows Event Log utility was not found."
        ) from exc

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Windows event collection timed out."
        ) from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()

        # wevtutil may report no matching records.
        # Do not treat other failures as an empty batch.
        if "no events" in stderr.lower():
            return [], 0

        raise RuntimeError(
            "Unable to collect Windows Security events: "
            + stderr[:500]
        )

    events, invalid = parse_windows_xml(result.stdout)

    # Sort by Windows record ID, not authentication timestamp.
    # Record IDs are the checkpoint ordering mechanism.
    events.sort(
        key=lambda event: int(
            event.get("windows_record_id") or 0
        )
    )

    return events, invalid
