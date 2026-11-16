
"""Build a clean AllamSec release candidate from Git-tracked files."""

import argparse
import fnmatch
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"

EXCLUDED_DIRECTORIES = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".vscode",
    ".idea",
    "tests",
    "build",
    "dist",
    "logs",
    "exports",
    "reports",
}

EXCLUDED_PATTERNS = {
    "*.db",
    "*.db-shm",
    "*.db-wal",
    "*.sqlite",
    "*.sqlite3",
    "*.log",
    "*.pyc",
    "*.pyo",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.zip",
    "*.egg-info",
    "*checkpoint*.json",
    ".env",
    ".env.*",
    "config.local.json",
}

REQUIRED_FILES = {
    "setup.bat",
    "start_allamsec.bat",
    "start_monitor.bat",
    "requirements.txt",
    "config.json",
    "config.example.json",
    "INSTALL.md",
    "dashboard/server.py",
    "dashboard/web_app.py",
    "app/monitor_launcher.py",
    "app/config_manager.py",
}


def is_excluded(relative_path):
    path = PurePosixPath(relative_path)

    if any(
        part in EXCLUDED_DIRECTORIES
        for part in path.parts
    ):
        return True

    if any(
        fnmatch.fnmatch(path.name.lower(), pattern.lower())
        for pattern in EXCLUDED_PATTERNS
    ):
        return True

    return False


def get_tracked_files():
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        check=True,
    )

    paths = []

    for raw_path in result.stdout.split(b"\0"):
        if not raw_path:
            continue

        relative = raw_path.decode(
            "utf-8",
            errors="surrogateescape",
        ).replace("\\", "/")

        if is_excluded(relative):
            continue

        full_path = PROJECT_ROOT / relative

        if full_path.is_symlink():
            raise RuntimeError(
                f"Symbolic links are not allowed: {relative}"
            )

        if not full_path.is_file():
            raise RuntimeError(
                f"Tracked file is missing: {relative}"
            )

        paths.append(relative)

    return sorted(set(paths))


def build_release(version):
    files = get_tracked_files()

    missing = REQUIRED_FILES - set(files)

    if missing:
        raise RuntimeError(
            "Missing required tracked files: "
            + ", ".join(sorted(missing))
        )

    DIST_DIR.mkdir(exist_ok=True)

    archive_path = DIST_DIR / f"AllamSec-{version}-rc.zip"

    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for relative in files:
            source = PROJECT_ROOT / relative
            destination = (
                f"AllamSec-{version}/"
                f"{relative}"
            )

            archive.write(
                source,
                arcname=destination,
            )

    return archive_path, files


def main():
    parser = argparse.ArgumentParser(
        description="Build an AllamSec release candidate."
    )

    parser.add_argument(
        "--version",
        default="1.0.0",
    )

    args = parser.parse_args()

    try:
        archive_path, files = build_release(
            args.version
        )

    except (
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as exc:
        print(
            f"Release build failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print("=" * 55)
    print("ALLAMSEC RELEASE BUILD")
    print("=" * 55)
    print("Archive:", archive_path)
    print("Files included:", len(files))
    print("Release candidate created.")
    print("=" * 55)

    return 0


if __name__ == "__main__":
    sys.exit(main())
