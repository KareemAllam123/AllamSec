
"""Persistent Windows Security event checkpoints for AllamSec."""

import json
import os
import tempfile
from pathlib import Path


DEFAULT_CHECKPOINT_PATH = (
    Path("database") / "windows_checkpoint.json"
)


def load_checkpoint(path=DEFAULT_CHECKPOINT_PATH):
    """Return the last processed Windows record ID, or None."""

    path = Path(path)

    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        record_id = data["last_record_id"]

        if type(record_id) is not int or record_id < 0:
            raise ValueError("Invalid checkpoint record ID.")

        return record_id

    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(
            f"Cannot load Windows checkpoint: {exc}"
        ) from exc


def save_checkpoint(record_id, path=DEFAULT_CHECKPOINT_PATH):
    """Atomically save the last successfully processed record ID."""

    if type(record_id) is not int or record_id < 0:
        raise ValueError("record_id must be a nonnegative integer.")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_name = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".checkpoint_",
            suffix=".tmp",
            delete=False,
        ) as file:
            temp_name = file.name
            json.dump(
                {"last_record_id": record_id},
                file,
                indent=2,
            )
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_name, path)

    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def clear_checkpoint(path=DEFAULT_CHECKPOINT_PATH):
    """Delete a checkpoint when explicitly requested."""

    Path(path).unlink(missing_ok=True)
