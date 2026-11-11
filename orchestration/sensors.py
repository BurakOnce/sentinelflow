import os
from collections.abc import Iterator
from pathlib import Path

import dagster as dg

LABELS_FILE = "ground_truth.jsonl"


def labels_path() -> Path:
    return Path(os.environ.get("LABELS_DIR", "data/labels")) / LABELS_FILE


def labels_cursor(path: Path) -> str | None:
    if not path.exists():
        return None
    stat = path.stat()
    return f"{stat.st_mtime_ns}-{stat.st_size}"


def ground_truth_sensor_factory(job_name: str) -> dg.SensorDefinition:
    @dg.sensor(
        job_name=job_name,
        minimum_interval_seconds=120,
        default_status=dg.DefaultSensorStatus.RUNNING,
    )
    def ground_truth_sensor(context: dg.SensorEvaluationContext) -> Iterator[dg.RunRequest]:
        cursor = labels_cursor(labels_path())
        if cursor is None or cursor == context.cursor:
            return
        context.update_cursor(cursor)
        yield dg.RunRequest(run_key=cursor)

    return ground_truth_sensor
