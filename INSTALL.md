
# Installing AllamSec

AllamSec is a Python-based security monitoring application that analyzes authentication events, detects suspicious activity, and displays security alerts through a local web dashboard.

## System Requirements

- Windows 10 or Windows 11
- Python 3 installed with the `py` launcher or available through PATH
- Internet access during installation
- Windows Security event log access for live monitoring

## Installation

### Option 1: Windows installer

1. Download the latest AllamSec release ZIP from GitHub.
2. Extract the ZIP into a folder.
3. Open the extracted folder.
4. Run `setup.bat` if Windows permits it.
5. Wait for installation to finish.

The installer creates a virtual environment, installs dependencies, and initializes the database.

### Option 2: Manual PowerShell installation

Use this method if the batch installer is blocked or unavailable.

Open PowerShell and navigate to the extracted AllamSec folder.

Run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "from database.db_manager import initialize_database; initialize_database()"
```

If the `py` launcher is unavailable, use a working Python 3 installation to create the virtual environment.

These commands do not require activating the virtual environment or changing PowerShell execution policies.

Do not disable Windows Smart App Control or other security protections to install AllamSec. If Windows blocks a downloaded file, use an installation method permitted by your organization's security policy.

## Starting AllamSec

### Recommended: Combined launcher

Open PowerShell in the AllamSec folder.

Run:

```powershell
.\.venv\Scripts\python.exe start_allamsec.py
```

The launcher:

- Starts the local security dashboard.
- Opens the dashboard in your default browser.
- Checks whether administrator privileges are available.
- Starts Windows Security monitoring when running with administrator privileges.
- Keeps the dashboard available without administrator privileges, but does not start the monitor.

Dashboard address:

http://127.0.0.1:5000

For live Windows Security monitoring, open PowerShell using **Run as administrator**, navigate to the AllamSec folder, and run the same command.

The launcher does not automatically request elevation.

### Start components separately

To start only the dashboard:

```powershell
.\.venv\Scripts\python.exe -m dashboard.server
```

To start only the Windows Security monitor:

```powershell
.\.venv\Scripts\python.exe -m app.monitor_launcher
```

The monitor may require an administrator PowerShell window or appropriate event-log permissions.

The original `start_allamsec.bat` and `start_monitor.bat` scripts remain available where permitted by Windows security settings.

## Configuration

Edit `config.json` to customize:

- Monitoring interval and maximum event batch size
- Brute-force detection threshold
- Detection time window
- Email notification preferences
- Local dashboard host and port

Restart AllamSec after changing configuration.

## Notifications

Email notifications are disabled by default.

AllamSec can create notification previews without sending real emails. Email delivery requires additional SMTP configuration.

## Stopping AllamSec

Press `Ctrl+C` in the PowerShell window running the combined launcher.

The launcher requests shutdown of its dashboard and monitoring subprocesses.

## Security Notes

- AllamSec is intended for educational use and security monitoring.
- It does not replace professional endpoint protection or enterprise security monitoring.
- Keep the dashboard bound to `127.0.0.1`.
- Do not expose the dashboard directly to the internet.
- Only monitor systems and event logs you are authorized to access.
- Run with administrator privileges only when necessary for event collection.

## Troubleshooting

### Dashboard does not open

Check the dashboard URL in `config.json`. Make sure another application is not already using the configured port.

### Python is not recognized

Install a supported Python 3 version and ensure Python or the `py` launcher is accessible.

### Windows Security events cannot be accessed

Verify that the PowerShell window has the required event-log permissions.

### Windows blocks a batch file

Do not disable Windows security protections. Use the documented manual PowerShell installation and Python launch commands where permitted.

### Monitoring does not start

If the launcher reports that administrator access is unavailable, restart it from an administrator PowerShell window if you are authorized to do so.

### Installation fails

Review the PowerShell error messages, confirm Python is installed correctly, and check internet access for dependency installation.
