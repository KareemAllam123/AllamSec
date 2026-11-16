
"""Centralized filesystem paths for AllamSec."""

import os
import sys
from pathlib import Path


IS_FROZEN = bool(getattr(sys, "frozen", False))

# Bundled resources are extracted or collected here by PyInstaller.
if IS_FROZEN:
    RESOURCE_ROOT = Path(
        getattr(sys, "_MEIPASS", Path(sys.executable).parent)
    ).resolve()
else:
    RESOURCE_ROOT = Path(__file__).resolve().parent.parent

# The executable's installation directory, or the development project.
if IS_FROZEN:
    INSTALL_ROOT = Path(sys.executable).resolve().parent
else:
    INSTALL_ROOT = RESOURCE_ROOT

# Writable files must not live in Program Files or the PyInstaller bundle.
if IS_FROZEN and os.name == "nt":
    local_appdata = os.environ.get("LOCALAPPDATA")

    if local_appdata:
        DATA_ROOT = Path(local_appdata) / "AllamSec"
    else:
        DATA_ROOT = Path.home() / "AppData" / "Local" / "AllamSec"
else:
    DATA_ROOT = RESOURCE_ROOT

DEFAULT_DB_PATH = DATA_ROOT / "database" / "allamsec.db"
DEFAULT_CHECKPOINT_PATH = (
    DATA_ROOT / "database" / "windows_checkpoint.json"
)
DEFAULT_CONFIG_PATH = DATA_ROOT / "config.json"
