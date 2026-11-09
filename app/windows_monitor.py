
"""Checkpoint-based Windows Security monitoring for AllamSec."""

import argparse
import logging
import time
from pathlib import Path

from app.windows_checkpoint import (
    DEFAULT_CHECKPOINT_PATH,
    load_checkpoint,
    save_checkpoint,
)
from app.windows_event_collector import (
    collect_windows_events_since,
)
from app.windows_ingest import ingest_windows_events


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger("AllamSec")


def process_windows_batch(
    checkpoint_path=DEFAULT_CHECKPOINT_PATH,
    max_events=500,
):
    """Collect and ingest all available batches up to a safety limit."""

    checkpoint = load_checkpoint(checkpoint_path)

    total_collected = 0
    total_new = 0
    total_remote = 0
    total_alerts = 0
    total_invalid = 0
    batches = 0

    max_batches = 100

    while batches < max_batches:
        events, invalid = collect_windows_events_since(
            last_record_id=checkpoint,
            batch_size=max_events,
        )

        total_invalid += invalid

        if invalid:
            raise RuntimeError(
                "Malformed Windows event XML encountered. "
                "Checkpoint was not advanced for this batch."
            )

        if not events:
            break

        record_ids = []

        for event in events:
            record_id = event.get("windows_record_id")

            try:
                parsed_id = int(record_id)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "Windows event is missing a valid record ID."
                ) from exc

            if parsed_id < 0:
                raise RuntimeError(
                    "Windows event has a negative record ID."
                )

            if checkpoint is not None and parsed_id <= checkpoint:
                raise RuntimeError(
                    "Collector returned a record at or before "
                    "the current checkpoint."
                )

            record_ids.append(parsed_id)

        if record_ids != sorted(set(record_ids)):
            raise RuntimeError(
                "Windows record IDs are not strictly increasing."
            )

        # This function must finish successfully before we
        # advance the checkpoint.
        results = ingest_windows_events(events)

        new_checkpoint = record_ids[-1]

        save_checkpoint(
            new_checkpoint,
            path=checkpoint_path,
        )

        checkpoint = new_checkpoint
        batches += 1

        total_collected += results["collected_events"]
        total_new += results["saved_events"]
        total_remote += results["remote_events"]
        total_alerts += results["saved_alerts"]

        logger.info(
            "Batch %s | Collected=%s | New=%s | "
            "Checkpoint=%s",
            batches,
            results["collected_events"],
            results["saved_events"],
            checkpoint,
        )

        if len(events) < max_events:
            break

    if batches >= max_batches:
        logger.warning(
            "Batch safety limit reached. Remaining events "
            "will be collected in the next monitoring cycle."
        )

    return {
        "collected_events": total_collected,
        "saved_events": total_new,
        "remote_events": total_remote,
        "saved_alerts": total_alerts,
        "invalid_lines": total_invalid,
        "batches": batches,
        "checkpoint": checkpoint,
    }


def monitor_windows(
    interval=60,
    max_events=500,
    max_cycles=None,
    checkpoint_path=DEFAULT_CHECKPOINT_PATH,
):
    """Continuously monitor Windows authentication events."""

    if interval < 5:
        raise ValueError(
            "Monitoring interval must be at least 5 seconds."
        )

    if not 1 <= max_events <= 10000:
        raise ValueError(
            "max_events must be between 1 and 10000."
        )

    if max_cycles is not None and max_cycles < 1:
        raise ValueError(
            "max_cycles must be at least 1."
        )

    logger.info("AllamSec Windows monitoring started.")
    logger.info("Collection interval: %s seconds", interval)
    logger.info("Checkpoint: %s", checkpoint_path)

    cycles = 0

    try:
        while True:
            cycles += 1

            logger.info(
                "Starting collection cycle %s...",
                cycles,
            )

            try:
                results = process_windows_batch(
                    checkpoint_path=checkpoint_path,
                    max_events=max_events,
                )

                logger.info(
                    "Collected=%s | New=%s | "
                    "Remote=%s | Alerts=%s | "
                    "Invalid=%s | Batches=%s | "
                    "Checkpoint=%s",
                    results["collected_events"],
                    results["saved_events"],
                    results["remote_events"],
                    results["saved_alerts"],
                    results["invalid_lines"],
                    results["batches"],
                    results["checkpoint"],
                )

            except (RuntimeError, OSError, ValueError):
                logger.exception(
                    "Windows event collection failed."
                )

            if max_cycles is not None and cycles >= max_cycles:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        logger.info("Monitoring stopped by user.")

    logger.info(
        "AllamSec monitoring finished after %s cycles.",
        cycles,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Checkpoint-based Windows Security monitoring."
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between collection cycles.",
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Events retrieved per batch.",
    )

    parser.add_argument(
        "--cycles",
        type=int,
        default=None,
        help="Stop after a number of cycles.",
    )

    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=DEFAULT_CHECKPOINT_PATH,
        help="Checkpoint JSON file location.",
    )

    args = parser.parse_args()

    monitor_windows(
        interval=args.interval,
        max_events=args.max_events,
        max_cycles=args.cycles,
        checkpoint_path=args.checkpoint,
    )


if __name__ == "__main__":
    main()
