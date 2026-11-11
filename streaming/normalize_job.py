import logging
from dataclasses import dataclass

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.streaming.query import StreamingQuery
from pyspark.sql.streaming.readwriter import DataStreamWriter

from storage.clickhouse.client import ClickHouseSettings
from streaming.parsing.spark_parser import PARSE_ERROR, normalize
from streaming.runtime import (
    BatchWriter,
    ClickHouseBatchWriter,
    KafkaBatchWriter,
    QueryProgressRecorder,
    await_all,
    build_session,
    read_kafka,
)
from streaming.schema import EVENT_FIELD_NAMES
from streaming.settings import (
    DLQ_TOPIC,
    NORMALIZED_TOPIC,
    RAW_TOPIC_PATTERN,
    StreamingSettings,
)

JOB_NAME = "normalize"
DEAD_LETTER_COLUMNS = (
    "source_type",
    "error",
    "topic",
    "kafka_partition",
    "kafka_offset",
    "ingest_time",
    "raw_message",
)
logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PublishTargets:
    events_table: BatchWriter
    events_topic: BatchWriter
    dead_letter_table: BatchWriter
    dead_letter_topic: BatchWriter


def raw_records(kafka_frame: DataFrame) -> DataFrame:
    return kafka_frame.select(
        F.regexp_extract("topic", r"^raw\.(.+)$", 1).alias("source_type"),
        F.col("value").cast("string").alias("raw_message"),
        F.col("timestamp").alias("ingest_time"),
        F.col("topic"),
        F.col("partition").alias("kafka_partition"),
        F.col("offset").alias("kafka_offset"),
    )


def bronze(raw: DataFrame) -> DataFrame:
    return raw.withColumn("ingest_date", F.to_date("ingest_time"))


def valid_events(parsed: DataFrame) -> DataFrame:
    return parsed.filter(F.col(PARSE_ERROR).isNull()).select(*EVENT_FIELD_NAMES)


def silver(parsed: DataFrame) -> DataFrame:
    return valid_events(parsed).withColumn("event_date", F.to_date("timestamp"))


def dead_letters(parsed: DataFrame) -> DataFrame:
    return parsed.filter(F.col(PARSE_ERROR).isNotNull()).select(
        "source_type",
        F.col(PARSE_ERROR).alias("error"),
        "topic",
        "kafka_partition",
        "kafka_offset",
        "ingest_time",
        "raw_message",
    )


def publish(batch: DataFrame, batch_id: int, targets: PublishTargets) -> None:
    batch.persist()
    try:
        events = valid_events(batch)
        failures = dead_letters(batch)
        targets.events_table.write(events, batch_id)
        targets.dead_letter_table.write(failures, batch_id)
        targets.events_topic.write(events, batch_id)
        targets.dead_letter_topic.write(failures, batch_id)
    finally:
        batch.unpersist()


def default_targets(settings: StreamingSettings) -> PublishTargets:
    clickhouse = ClickHouseSettings()
    return PublishTargets(
        events_table=ClickHouseBatchWriter("events", EVENT_FIELD_NAMES, "normalize", clickhouse),
        events_topic=KafkaBatchWriter(
            settings.kafka_bootstrap_servers, NORMALIZED_TOPIC, "event_id", EVENT_FIELD_NAMES
        ),
        dead_letter_table=ClickHouseBatchWriter(
            "parse_failures", DEAD_LETTER_COLUMNS, "normalize-dlq", clickhouse
        ),
        dead_letter_topic=KafkaBatchWriter(
            settings.kafka_bootstrap_servers, DLQ_TOPIC, "source_type", DEAD_LETTER_COLUMNS
        ),
    )


def start_queries(
    kafka_frame: DataFrame,
    settings: StreamingSettings,
    targets: PublishTargets,
    available_now: bool = False,
) -> list[StreamingQuery]:
    raw = raw_records(kafka_frame)
    parsed = normalize(raw)

    def configure(name: str, writer: DataStreamWriter) -> DataStreamWriter:
        writer = writer.queryName(f"{JOB_NAME}_{name}").option(
            "checkpointLocation", settings.checkpoint(JOB_NAME, name)
        )
        if available_now:
            return writer.trigger(availableNow=True)
        return writer.trigger(processingTime=settings.trigger_interval)

    bronze_query = configure(
        "bronze",
        bronze(raw)
        .writeStream.format("parquet")
        .partitionBy("source_type", "ingest_date")
        .option("path", settings.lake_path("bronze", "raw_logs"))
        .option("retention", settings.sink_retention),
    ).start()
    silver_query = configure(
        "silver",
        silver(parsed)
        .writeStream.format("parquet")
        .partitionBy("source_type", "event_date")
        .option("path", settings.lake_path("silver", "events"))
        .option("retention", settings.sink_retention),
    ).start()
    publish_query = configure(
        "publish",
        parsed.writeStream.foreachBatch(lambda batch, batch_id: publish(batch, batch_id, targets)),
    ).start()
    return [bronze_query, silver_query, publish_query]


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = StreamingSettings()
    spark: SparkSession = build_session("sentinelflow-normalize", settings)
    spark.streams.addListener(QueryProgressRecorder(JOB_NAME))
    kafka_frame = read_kafka(spark, settings, subscribe_pattern=RAW_TOPIC_PATTERN)
    start_queries(kafka_frame, settings, default_targets(settings))
    await_all(spark)


if __name__ == "__main__":
    main()
