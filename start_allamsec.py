
"""Start the AllamSec dashboard and Windows Security monitor together."""

import ctypes
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

from app.config_manager import DEFAULT_CONFIG_PATH, load_config


PROJECT_ROOT = Path(__file__).resolve().parent


def is_administrator():
    """Check whether the current Windows process is elevated."""
    if os.name != "nt":
        return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def start_process(module):
    """Launch an AllamSec component using the current Python interpreter."""
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            module,
        ],
        cwd=PROJECT_ROOT,
    )


def stop_process(process, name):
    """Request a child process to stop, then wait for it."""
    if process is None or process.poll() is not None:
        return

    print(f"Stopping {name}...", flush=True)
    process.terminate()

    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        print(f"{name} did not stop in time. Forcing shutdown.")
        process.kill()
        process.wait()


def main():
    os.chdir(PROJECT_ROOT)

    print("=" * 55)
    print("ALLAMSEC SECURITY PLATFORM")
    print("Version: 1.0.1")
    print("=" * 55)

    dashboard_process = None
    monitor_process = None

    try:
        config = load_config(DEFAULT_CONFIG_PATH)

        host = config["dashboard"]["host"]
        port = config["dashboard"]["port"]
        dashboard_url = f"http://{host}:{port}"

        print("\n[1/2] Starting security dashboard...", flush=True)
        dashboard_process = start_process("dashboard.server")

        time.sleep(2)

        if dashboard_process.poll() is not None:
            raise RuntimeError(
                "The dashboard stopped unexpectedly. "
                "Check the error messages above."
            )

        print(f"Dashboard: {dashboard_url}", flush=True)

        print("\n[2/2] Checking Windows monitoring permissions...")

        if is_administrator():
            print("Administrator access confirmed.")
            print("Starting continuous Windows Security monitoring...")
            monitor_process = start_process("app.monitor_launcher")
        else:
            print(
                "Administrator access is not available. "
                "Windows Security monitoring was not started."
            )
            print(
                "To enable monitoring, close AllamSec and "
                "run your terminal as Administrator."
            )

        print("\nOpening dashboard in your browser...")
        webbrowser.open(dashboard_url)

        print("\n" + "=" * 55)
        print("ALLAMSEC IS RUNNING")
        print("=" * 55)
        print(f"Dashboard: {dashboard_url}")
        print(
            "Windows monitor:",
            "RUNNING" if monitor_process else "NOT STARTED",
        )
        print("Press CTRL+C to stop AllamSec.")
        print("=" * 55, flush=True)

        while True:
            if dashboard_process.poll() is not None:
                print("\nDashboard process has stopped.")
                break

            if monitor_process is not None and monitor_process.poll() is not None:
                print("\nWindows monitor has stopped unexpectedly.")
                print("The dashboard will remain available.")
                monitor_process = None

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nShutdown requested.")

    except (OSError, ValueError, RuntimeError) as exc:
        print(f"\nAllamSec startup error: {exc}", file=sys.stderr)
        return 1

    finally:
        stop_process(monitor_process, "Windows monitor")
        stop_process(dashboard_process, "Security dashboard")
        print("AllamSec stopped.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
