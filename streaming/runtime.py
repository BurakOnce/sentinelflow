import logging
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

from pyspark.sql import Column, DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.streaming.listener import StreamingQueryListener

from storage.clickhouse.client import ClickHouseSettings, connect, insert_rows
from streaming.settings import StreamingSettings

JSON_OPTIONS = {"timestampFormat": "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX", "ignoreNullFields": "false"}
logger = logging.getLogger(__name__)


def build_session(app_name: str, settings: StreamingSettings) -> SparkSession:
    builder = (
        SparkSession.builder.appName(app_name)
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.shuffle.partitions", os.environ.get("SPARK_SHUFFLE_PARTITIONS", "4"))
        .config("spark.sql.streaming.stateStore.stateSchemaCheck", "true")
        .config("spark.hadoop.fs.s3a.endpoint", settings.s3_endpoint)
        .config("spark.hadoop.fs.s3a.access.key", settings.s3_access_key)
        .config("spark.hadoop.fs.s3a.secret.key", settings.s3_secret_key)
        .config("spark.hadoop.fs.s3a.path.style.access", "true")
        .config("spark.hadoop.fs.s3a.connection.ssl.enabled", "false")
        .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem")
        .config(
            "spark.hadoop.fs.s3a.aws.credentials.provider",
            "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
        )
    )
    return builder.getOrCreate()


def read_kafka(
    spark: SparkSession, settings: StreamingSettings, *, subscribe_pattern: str
) -> DataFrame:
    return (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", settings.kafka_bootstrap_servers)
        .option("subscribePattern", subscribe_pattern)
        .option("startingOffsets", settings.starting_offsets)
        .option("maxOffsetsPerTrigger", settings.max_offsets_per_trigger)
        .option("failOnDataLoss", "false")
        .load()
    )


def json_value(columns: Sequence[str]) -> Column:
    return F.to_json(F.struct(*columns), JSON_OPTIONS)


class BatchWriter(Protocol):
    def write(self, frame: DataFrame, batch_id: int) -> None: ...


class KafkaBatchWriter:
    def __init__(self, bootstrap_servers: str, topic: str, key: str, columns: Sequence[str]):
        self._bootstrap_servers = bootstrap_servers
        self._topic = topic
        self._key = key
        self._columns = list(columns)

    def write(self, frame: DataFrame, batch_id: int) -> None:
        (
            frame.select(
                F.col(self._key).cast("string").alias("key"),
                json_value(self._columns).alias("value"),
            )
            .write.format("kafka")
            .option("kafka.bootstrap.servers", self._bootstrap_servers)
            .option("topic", self._topic)
            .save()
        )


class ClickHouseBatchWriter:
    def __init__(
        self,
        table: str,
        columns: Sequence[str],
        token_prefix: str,
        settings: ClickHouseSettings | None = None,
    ) -> None:
        self._table = table
        self._columns = list(columns)
        self._token_prefix = token_prefix
        self._settings = settings or ClickHouseSettings()

    def write(self, frame: DataFrame, batch_id: int) -> None:
        arrow = frame.select(*self._columns).toArrow()
        if arrow.num_rows == 0:
            return
        client = connect(self._settings)
        try:
            client.insert_arrow(
                self._table,
                arrow,
                settings={"insert_deduplication_token": f"{self._token_prefix}-{batch_id}"},
            )
        finally:
            client.close()


class QueryProgressRecorder(StreamingQueryListener):
    def __init__(self, job: str, settings: ClickHouseSettings | None = None) -> None:
        self._job = job
        self._settings = settings or ClickHouseSettings()

    def onQueryStarted(self, event: Any) -> None:
        logger.info("query started %s", event.name)

    def onQueryIdle(self, event: Any) -> None:
        return None

    def onQueryTerminated(self, event: Any) -> None:
        logger.warning("query terminated %s %s", event.id, event.exception)

    def onQueryProgress(self, event: Any) -> None:
        progress = event.progress
        behind = [
            float(value)
            for source in progress.sources
            for key, value in (source.metrics or {}).items()
            if key == "maxOffsetsBehindLatest" and value is not None
        ]
        row = [
            self._job,
            progress.name or "unnamed",
            progress.batchId,
            datetime.now(UTC),
            progress.numInputRows,
            _finite(progress.inputRowsPerSecond),
            _finite(progress.processedRowsPerSecond),
            int(progress.durationMs.get("triggerExecution", 0)),
            max(behind, default=0.0),
        ]
        try:
            client = connect(self._settings)
            try:
                insert_rows(client, "pipeline_batches", PIPELINE_BATCH_COLUMNS, [row])
            finally:
                client.close()
        except Exception:
            logger.exception("failed to record progress for %s", progress.name)


PIPELINE_BATCH_COLUMNS = (
    "job",
    "query",
    "batch_id",
    "processed_at",
    "input_rows",
    "input_rows_per_second",
    "processed_rows_per_second",
    "duration_ms",
    "offsets_behind_latest",
)


def _finite(value: float | None) -> float:
    return value if value is not None and value == value and abs(value) != float("inf") else 0.0


def await_all(spark: SparkSession) -> None:
    try:
        spark.streams.awaitAnyTermination()
    finally:
        for query in spark.streams.active:
            query.stop()
