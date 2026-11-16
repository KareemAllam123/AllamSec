
# AllamSec

### Windows Security Monitoring & Threat Detection Platform

**Version 1.0.1**

AllamSec is a Python-based cybersecurity monitoring application that collects Windows Security events, analyzes authentication activity, detects suspicious behavior, and presents security findings through a local web dashboard.

Built as an independent cybersecurity project, AllamSec demonstrates security operations center (SOC) concepts including event collection, log analysis, threat detection, event correlation, risk scoring, alert management, and security visualization.

## Key Features

### Windows Security Event Monitoring
- Collects authentication-related events from Windows Security logs.
- Supports continuous monitoring with configurable collection intervals.
- Tracks collection progress using checkpoints.
- Stores collected events in a local SQLite database.

### Threat Detection
- Detects repeated failed authentication attempts.
- Identifies potentially suspicious successful logins following repeated failures.
- Supports configurable detection thresholds and time windows.
- Includes network event parsing and port-scan detection capabilities.
- Correlates relevant events to generate security alerts.

### Risk Scoring and Alert Management
- Assigns risk scores and severity classifications to detected threats.
- Records alerts for further investigation.
- Supports alert status updates and investigation notes.
- Distinguishes between suspicious activity and confirmed compromise.

### Web Dashboard
- Local browser-based dashboard built with Flask.
- Security overview and event statistics.
- Windows Security event viewer.
- Security alert management.
- Threat analytics and visualizations.
- Notification Center.

### Notifications
- Generates notification previews for detected security threats.
- Supports configurable severity thresholds.
- Email delivery is disabled by default.

### Automated Testing
- 241 passing automated tests and 2 passing subtests as of the v1.0.1 release candidate.
- Covers event parsing, threat detection, database operations, and other application functionality.

## Technologies

- Python
- Flask
- Waitress
- SQLite
- HTML, CSS, and JavaScript
- Windows Security Event Logs
- Git and GitHub
- Python unittest and pytest

## Installation

### Requirements
- Windows 10 or Windows 11
- Python 3
- Internet connection for dependency installation
- Appropriate Windows event-log permissions for live monitoring

Download the latest release ZIP from:

https://github.com/KareemAllam123/AllamSec/releases

Extract the ZIP into a folder.

### Install using PowerShell

Open PowerShell inside the extracted AllamSec folder and run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "from database.db_manager import initialize_database; initialize_database()"
```

The `setup.bat` installer is also available on systems where Windows permits it.

For additional instructions and troubleshooting, see [INSTALL.md](INSTALL.md).

## Running AllamSec

### Combined Dashboard and Monitor

From the AllamSec directory, run:

```powershell
.\.venv\Scripts\python.exe start_allamsec.py
```

This launcher:

1. Starts the local dashboard.
2. Opens the dashboard in your browser.
3. Checks administrator permissions.
4. Starts continuous Windows Security monitoring when administrator privileges are available.

Dashboard URL:

http://127.0.0.1:5000

For live Windows Security monitoring, launch PowerShell as Administrator and run the same command.

Without administrator privileges, the dashboard can still run, but the combined launcher skips Windows monitoring.

### Starting Components Individually

Dashboard:

```powershell
.\.venv\Scripts\python.exe -m dashboard.server
```

Windows monitor:

```powershell
.\.venv\Scripts\python.exe -m app.monitor_launcher
```

Press `Ctrl+C` to stop the application.

## Configuration

AllamSec uses `config.json` to configure monitoring and detection behavior.

Default settings include:

| Setting | Default |
|---|---|
| Monitoring interval | 60 seconds |
| Maximum events per batch | 500 |
| Failed login threshold | 5 |
| Detection window | 60 seconds |
| Minimum notification severity | HIGH |
| Email notifications | Disabled |
| Dashboard address | 127.0.0.1:5000 |

## Detection Examples

### Possible Brute-Force Attack

Five failed authentication attempts within the configured 60-second window can trigger a HIGH-severity alert when they satisfy the detection rule's correlation conditions.

### Possible Account Compromise

A successful authentication following repeated failed attempts can trigger a CRITICAL-severity alert when it meets the detection criteria.

These alerts indicate potentially suspicious behavior and do not establish that an account has actually been compromised.

## Running Tests

From the development repository, install pytest if necessary:

```powershell
python -m pip install pytest
```

Then run:

```powershell
python -m pytest -q
```

The v1.0.1 release candidate passed 241 tests and 2 subtests.

Tests are included in the development repository but excluded from downloadable release ZIP files.

## Project Structure

```text
AllamSec/
|-- app/                  # Application and Windows monitoring
|-- dashboard/            # Web dashboard and static assets
|-- database/             # SQLite database management
|-- detection/            # Threat detection modules
|-- tests/                # Automated tests (development repo)
|-- tools/                # Release and development utilities
|-- config.json           # Application configuration
|-- INSTALL.md            # Detailed installation instructions
|-- README.md
|-- requirements.txt
|-- setup.bat
|-- start_allamsec.py     # Combined launcher
|-- start_allamsec.bat    # Dashboard-only launcher
|-- start_monitor.bat     # Monitor-only launcher
```

## Security Considerations

AllamSec is an educational and defensive security monitoring project.

- Only monitor systems and logs you are authorized to access.
- Keep the dashboard bound to the local loopback address.
- Do not expose the dashboard directly to the internet.
- Do not disable Windows security protections to install AllamSec.
- Use administrator privileges only when necessary.
- Review generated alerts before drawing conclusions about suspicious activity.

AllamSec is not a replacement for enterprise SIEM, endpoint detection, or professional incident response solutions.

## Release Status

**Current Version:** 1.0.1

**Status:** Release candidate

Version 1.0.1 improves installation documentation, introduces a combined application launcher, and updates dashboard version information.

Development and additional security capabilities are ongoing.
