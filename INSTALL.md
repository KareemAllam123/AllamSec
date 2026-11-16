# Installing AllamSec

AllamSec is a Python-based security monitoring application that analyzes authentication events, detects suspicious activity, and displays security alerts through a local web dashboard.

## System Requirements

- Windows 10 or Windows 11
- Python 3 installed and accessible from the command line
- Internet access during installation to download Python dependencies
- Access to the Windows Security event log for live monitoring

## Installation

1. Download the AllamSec release ZIP.
2. Extract the ZIP into a folder.
3. Open the extracted folder.
4. Run `setup.bat`.
5. Wait for dependency installation and database initialization to complete.

The installer creates a Python virtual environment and installs the required packages.

## Starting the Dashboard

Run:

`start_allamsec.bat`

Open the dashboard in your browser:

`http://127.0.0.1:5000`

The dashboard runs locally and is not intended to be accessible over the internet.

Keep the dashboard window open while using AllamSec.

## Starting Windows Security Monitoring

Run:

`start_monitor.bat`

The monitor reads Windows authentication events and checks for suspicious activity.

Depending on your Windows configuration, elevated privileges may be required to access the Security event log.

The monitoring window must remain open while monitoring is active.

## Configuration

Edit `config.json` to customize:

- Monitoring interval and maximum event batch size
- Brute-force detection threshold
- Detection time window
- Notification preferences
- Local dashboard port

Restart the affected component after changing its configuration.

## Notifications

Email notifications are disabled by default. The application can record notification previews without sending real emails.

Email delivery requires additional SMTP configuration.

## Stopping AllamSec

Press `Ctrl+C` in the dashboard or monitoring terminal.

## Important Security Notes

AllamSec is intended for security monitoring and educational use. It does not replace professional endpoint protection or enterprise security monitoring.

Keep the dashboard bound to `127.0.0.1`. Do not expose it directly to the internet.

Only monitor systems and event logs you are authorized to access.

## Troubleshooting

**Dashboard doesn't open:** Make sure `start_allamsec.bat` is running and use the port configured in `config.json`.

**Python isn't recognized:** Install Python 3 and ensure it is available through the `py` launcher or your system PATH.

**Windows Security events cannot be accessed:** Check whether your account has the required event-log permissions.

**Installation fails:** Review the errors displayed by `setup.bat` and confirm that your computer can access Python's package repository.