# AllamSec

### Security Monitoring & Threat Detection Platform

**AllamSec** is a Python-based cybersecurity project designed to analyze security logs, detect suspicious authentication activity, and generate security alerts.

The project simulates a lightweight Security Operations Center (SOC) monitoring environment, helping demonstrate fundamental cybersecurity concepts such as log analysis, threat detection, event correlation, and security monitoring.

AllamSec is currently under active development, with additional detection capabilities and a web-based monitoring dashboard planned for future releases.

---

## Project Overview

AllamSec analyzes simulated authentication logs to identify potentially malicious activity.

The application extracts authentication events, validates log entries, calculates security statistics, and detects suspicious login patterns using configurable detection rules.

Currently, AllamSec can identify:

- Repeated failed login attempts that may indicate brute-force attacks.
- Successful logins following repeated failed attempts that may indicate account compromise.
- Suspicious authentication activity associated with individual IP addresses and user accounts.
- Invalid or malformed authentication log entries.

The goal is to develop AllamSec into a lightweight cybersecurity monitoring platform with additional network threat detection, risk scoring, event storage, and security visualization capabilities.

## Current Features

### 1. Authentication Log Analysis

AllamSec reads authentication log files and extracts:

- Event timestamps
- Authentication event types
- Usernames
- Source IP addresses

The application validates each log entry and rejects malformed or unsupported events.

### 2. Authentication Statistics

AllamSec generates a report containing:

- Total authentication events
- Successful login attempts
- Failed login attempts
- Failed-login percentage
- Unique source IP addresses
- Authentication statistics for individual IP addresses
- Invalid log entry counts

### 3. Brute-Force Attack Detection

AllamSec identifies possible brute-force attacks by monitoring repeated failed authentication attempts.

**Default detection settings:**

| Setting | Value |
|---|---|
| Failed login threshold | 5 attempts |
| Detection window | 60 seconds |
| Alert severity | HIGH |
| Detection method | Sliding time window |
| Event correlation | Source IP and username |

When five failed login attempts occur against the same account from the same IP address within 60 seconds, AllamSec generates a security alert.

**Example alert:**

```text
Alert Type:      POSSIBLE_BRUTE_FORCE
Severity:        HIGH
Source IP:       192.168.1.10
Target Account:  admin
Failed Attempts: 5
First Attempt:   2026-10-28 10:00:01
Last Attempt:    2026-10-28 10:00:09
Time Window:     60 seconds
```

### 4. Possible Account Compromise Detection

AllamSec identifies potentially suspicious successful logins occurring shortly after repeated failed authentication attempts.

If a successful login occurs from the same IP address into the same account within 60 seconds of a brute-force detection, AllamSec generates a **CRITICAL** security alert.

**Example alert:**

```text
Alert Type:      POSSIBLE_ACCOUNT_COMPROMISE
Severity:        CRITICAL
Source IP:       192.168.1.10
Target Account:  admin
Failed Attempts: 5
First Attempt:   2026-10-28 10:00:01
Last Attempt:    2026-10-28 10:00:15
Time Window:     60 seconds
```

This detection indicates potentially suspicious authentication activity. It does not confirm that an account has been compromised.

### 5. Automated Testing

AllamSec uses Python's built-in `unittest` framework to test authentication parsing and threat detection.

The current test suite includes:

- Authentication event validation
- IPv4 and IPv6 address validation
- Invalid timestamp handling
- Malformed log detection
- Brute-force detection
- Configurable detection thresholds
- Sliding time-window behavior
- Multiple attacker detection
- Possible account compromise detection
- Duplicate alert prevention
- Authentication event ordering
- Successful-login reset behavior

The test suite currently contains **28 tests** across the authentication parser and brute-force detection modules.

---

## Technologies

### Currently Used

- **Python:** Core application development and security detection logic
- **Python unittest:** Automated testing
- **Git:** Version control
- **GitHub:** Source code hosting
- **Python Standard Library:** File handling, timestamps, IP validation, and event processing

### Planned Technologies

- **Flask:** Web-based monitoring dashboard
- **SQLite:** Security event and alert storage
- **HTML/CSS/JavaScript:** Dashboard interface
- **Linux:** Controlled security testing environment

---

## Project Structure

```text
AllamSec/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── parser.py
│   └── analyzer.py
│
├── detection/
│   ├── __init__.py
│   └── brute_force.py
│
├── tests/
│   ├── test_parser.py
│   └── test_brute_force.py
│
├── data/
│   └── sample_logs/
│       └── authentication.log
│
├── dashboard/
│
├── .gitignore
├── README.md
└── requirements.txt
```

The `dashboard` directory is reserved for future development.

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/KareemAllam123/AllamSec.git
```

Navigate into the project directory:

```bash
cd AllamSec
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate the Virtual Environment

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

The current application uses Python's standard library and does not require additional third-party packages.

### 5. Run AllamSec

From the project's root directory:

```bash
python -m app.main
```

The application will:

1. Initialize the monitoring environment.
2. Load authentication logs.
3. Validate and parse authentication events.
4. Generate authentication statistics.
5. Execute brute-force detection.
6. Identify potentially suspicious successful logins.
7. Display security alerts in the terminal.

---

## Running Automated Tests

Run all automated tests from the project's root directory:

```bash
python -m unittest discover -s tests -v
```

Run only the authentication parser tests:

```bash
python -m unittest discover -s tests -p "test_parser.py" -v
```

Run only the brute-force detection tests:

```bash
python -m unittest discover -s tests -p "test_brute_force.py" -v
```

---

## Development Roadmap

AllamSec is being developed incrementally, with each phase
introducing additional security monitoring capabilities.

| Phase | Development Goal | Status |
|---|---|---|
| Phase 1 | Project Setup & Architecture | Completed |
| Phase 2 | Authentication Log Analysis | Completed |
| Phase 3 | Threat Detection & Event Correlation | Completed |
| Phase 4 | Network Monitoring & Port-Scan Detection | Planned |
| Phase 5 | Risk Scoring & Threat Classification | Planned |
| Phase 6 | Database Integration | Planned |
| Phase 7 | Web Dashboard & Visualization | Planned |
| Phase 8 | Testing, Optimization & Documentation | Planned |

---

## Security and Ethical Use

AllamSec is an educational cybersecurity project intended for learning and demonstrating defensive security monitoring techniques.

All sample authentication logs included in this repository are fictional.

Security testing should only be conducted in environments where explicit authorization has been granted.

AllamSec is not intended to replace production-grade security monitoring or intrusion detection systems.

---

## Development Status

**Current Version:** 0.3.0

**Status:** Active Development

AllamSec is an ongoing independent cybersecurity project.

Future updates will expand the platform with network monitoring,
additional detection rules, persistent event storage, and a
web-based security dashboard.