import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from conftest import SIMULATION_START, requires_spark_filesystem

from simulator.simulation import AttackRequest, SimulationPlan, simulate
from streaming.parsing.python_parser import ParseError, parse_line
from streaming.schema import EVENT_FIELD_NAMES

if TYPE_CHECKING:
    from pyspark.sql import DataFrame, SparkSession

pytestmark = pytest.mark.spark
INGEST_TIME = datetime(2026, 9, 28, 12, tzinfo=UTC)
BROKEN_LINES = [
    ("nginx", ""),
    ("nginx", "garbage"),
    ("nginx", '1.2.3.4 - - [28/Foo/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'),
    ("ssh", "2026-09-28T10:15:30.123456+00:00 bastion-01 sshd[1]: Connection closed"),
    ("ssh", "2026-09-28T10:15:30.123456+00:00 h sshd[1]: Invalid user x from 1.2.3.4 port 99999"),
    ("firewall", "2026-09-28T10:15:30.123456+00:00 fw kernel: FW ACTION=LOG"),
    ("app", "{broken"),
    ("app", "[1]"),
    ("app", '{"timestamp":"2026-09-28T10:15:30.123Z","ip":"1.2.3.4"}'),
    ("app", '{"timestamp":"2026-09-28T10:15:30.123Z","ip":"1.2.3","result":"success"}'),
    ("app", '{"timestamp":"yesterday","ip":"1.2.3.4","result":"success"}'),
    ("windows", "anything"),
]


def simulated_lines() -> list[tuple[str, str]]:
    plan = SimulationPlan(
        start=SIMULATION_START + timedelta(hours=8),
        end=SIMULATION_START + timedelta(hours=9),
        users=40,
        attacks=tuple(AttackRequest.parse("all:0.2")),
    )
    return [(str(record.event.source), record.event.render()) for record in simulate(plan)]


def python_view(source_type: str, raw: str) -> dict[str, Any]:
    try:
        event = parse_line(source_type, raw, INGEST_TIME)
    except ParseError as error:
        return {"parse_error": str(error.code)}
    values = event.as_dict()
    values["timestamp"] = int(event.timestamp.timestamp() * 1_000_000)
    values["ingest_time"] = int(event.ingest_time.timestamp() * 1_000_000)
    return values | {"parse_error": None}


def spark_view(spark: "SparkSession", lines: list[tuple[str, str]]) -> list[dict[str, Any]]:
    from pyspark.sql import functions as F

    from streaming.parsing.spark_parser import normalize

    frame = spark.createDataFrame(
        [(index, source, raw, INGEST_TIME) for index, (source, raw) in enumerate(lines)],
        "row_id long, source_type string, raw_message string, ingest_time timestamp",
    )
    parsed = normalize(frame).withColumns(
        {"timestamp": F.unix_micros("timestamp"), "ingest_time": F.unix_micros("ingest_time")}
    )
    rows = sorted(parsed.collect(), key=lambda row: row["row_id"])
    views = []
    for row in rows:
        values = row.asDict()
        values.pop("row_id")
        if values["parse_error"] is not None:
            views.append({"parse_error": values["parse_error"]})
        else:
            views.append({name: values[name] for name in EVENT_FIELD_NAMES} | {"parse_error": None})
    return views


def test_spark_parser_matches_python_parser(spark: "SparkSession") -> None:
    lines = simulated_lines() + BROKEN_LINES
    expected = [python_view(source, raw) for source, raw in lines]
    actual = spark_view(spark, lines)
    mismatches = [
        (lines[index], want, got)
        for index, (want, got) in enumerate(zip(expected, actual, strict=True))
        if want != got
    ]
    assert mismatches == []
    assert sum(view["parse_error"] is None for view in actual) >= len(lines) - len(BROKEN_LINES)


def kafka_rows(lines: list[tuple[str, str]], offset: int = 0) -> list[dict[str, Any]]:
    return [
        {
            "topic": f"raw.{source}",
            "value": raw,
            "timestamp": (INGEST_TIME + timedelta(seconds=index)).isoformat(),
            "partition": 0,
            "offset": offset + index,
        }
        for index, (source, raw) in enumerate(lines)
    ]


class CollectingWriter:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self.batches: list[int] = []

    def write(self, frame: "DataFrame", batch_id: int) -> None:
        self.batches.append(batch_id)
        self.rows.extend(row.asDict() for row in frame.collect())


def test_publish_splits_valid_events_and_dead_letters(spark: "SparkSession") -> None:
    from pyspark.sql import functions as F

    from streaming.normalize_job import PublishTargets, publish, raw_records
    from streaming.parsing.spark_parser import normalize

    lines = simulated_lines()[:50] + BROKEN_LINES
    frame = spark.createDataFrame(kafka_rows(lines)).withColumn(
        "timestamp", F.to_timestamp("timestamp")
    )
    writers = [CollectingWriter() for _ in range(4)]
    publish(normalize(raw_records(frame)), 7, PublishTargets(*writers))
    events_table, events_topic, dlq_table, dlq_topic = writers
    assert len(events_table.rows) == 50
    assert events_table.rows == events_topic.rows
    assert len(dlq_table.rows) == len(BROKEN_LINES)
    assert {row["error"] for row in dlq_table.rows} >= {"unrecognized_format", "invalid_json"}
    assert all(row["raw_message"] is not None for row in dlq_topic.rows)
    assert events_table.batches == [7]


def write_kafka_batch(directory: Path, name: str, rows: list[dict[str, Any]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")


@requires_spark_filesystem
def test_normalize_job_restarts_without_loss_or_duplicates(
    spark: "SparkSession", tmp_path: Path
) -> None:
    from pyspark.sql import functions as F

    from streaming.normalize_job import PublishTargets, start_queries
    from streaming.settings import StreamingSettings

    settings = StreamingSettings(
        lake_root=f"file://{tmp_path}/lake/", checkpoint_root=f"file://{tmp_path}/checkpoints"
    )
    inbox = tmp_path / "inbox"
    schema = "topic string, value string, timestamp string, partition int, offset long"
    lines = simulated_lines()
    first, second = lines[:300], lines[300:600]
    writers = [CollectingWriter() for _ in range(4)]

    def run() -> None:
        source = (
            spark.readStream.schema(schema)
            .json(str(inbox))
            .withColumn("timestamp", F.to_timestamp("timestamp"))
        )
        for query in start_queries(source, settings, PublishTargets(*writers), available_now=True):
            query.awaitTermination()

    write_kafka_batch(inbox, "a.json", kafka_rows(first + BROKEN_LINES))
    run()
    write_kafka_batch(inbox, "b.json", kafka_rows(second, offset=10_000))
    run()

    silver = spark.read.parquet(settings.lake_path("silver", "events"))
    bronze = spark.read.parquet(settings.lake_path("bronze", "raw_logs"))
    assert bronze.count() == len(first) + len(BROKEN_LINES) + len(second)
    assert silver.count() == len(first) + len(second)
    assert silver.filter("source_type = 'windows'").count() == 0
    assert set(bronze.columns) >= {"source_type", "ingest_date", "raw_message"}
    assert set(silver.columns) >= {"source_type", "event_date", *EVENT_FIELD_NAMES}
    events_table = writers[0]
    assert len(events_table.rows) == len(first) + len(second)
    assert len(writers[2].rows) == len(BROKEN_LINES)
