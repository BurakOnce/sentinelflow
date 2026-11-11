import json
import logging
import os
import threading
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any

from confluent_kafka import Producer
from pyspark.sql import DataFrame, Row, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.streaming.query import StreamingQuery
from pyspark.sql.streaming.readwriter import DataStreamWriter

from detections.engine.alerts import Alert, AlertManager
from detections.engine.detectors import DETECTORS, StateStore
from detections.engine.hits import EPOCH, Hit, WindowEntry, evaluate_window
from detections.engine.loader import RuleSet, load_rules
from detections.engine.model import CorrelationRule, DetectorRule, entity_type, parse_duration
from detections.engine.spark_backend import (
    aggregate_windows,
    compile_expression,
    correlation_entries,
    single_event_matches,
)
from enrichment.alert_enrichment import AlertEnricher, ClickHouseBaselineLookup
from enrichment.geo import ClickHouseGeoLookup, GeoLookup
from enrichment.risk import load_weights
from enrichment.threat_intel import (
    AbuseIpDbProvider,
    LookupProvider,
    ThreatIntelService,
    ThreatIntelStore,
)
from storage.clickhouse.client import ClickHouseSettings, connect
from streaming.alert_sink import (
    AlertSink,
    ClickHouseStateStore,
    load_recent_alerts,
    recurrence_counter,
)
from streaming.runtime import (
    JSON_OPTIONS,
    QueryProgressRecorder,
    await_all,
    build_session,
    read_kafka,
)
from streaming.schema import spark_schema
from streaming.settings import ALERTS_TOPIC, NORMALIZED_TOPIC, StreamingSettings

JOB_NAME = "detect"
Publisher = Callable[[list[Alert], str], None]
logger = logging.getLogger(__name__)


def from_micros(value: int) -> datetime:
    return EPOCH + timedelta(microseconds=value)


def parse_events(kafka_frame: DataFrame) -> DataFrame:
    parsed = F.from_json(F.col("value").cast("string"), spark_schema(), JSON_OPTIONS)
    return kafka_frame.select(parsed.alias("event")).select("event.*")


class DetectionHandler:
    def __init__(
        self,
        rules: RuleSet,
        manager: AlertManager,
        publish: Publisher,
        state: StateStore,
        geo: GeoLookup,
        after_detectors: Callable[[], None] = lambda: None,
    ) -> None:
        self._rules = rules
        self._manager = manager
        self._publish = publish
        self._state = state
        self._geo = geo
        self._after_detectors = after_detectors
        self._detector_lock = threading.Lock()

    def _emit(self, hits: Sequence[Hit], token: str) -> None:
        changed = self._manager.apply(hits)
        if changed:
            self._publish(changed, token)

    def single(self, batch: DataFrame, batch_id: int) -> None:
        self._emit(self.single_hits(batch), f"single-{batch_id}")

    def correlation(self, batch: DataFrame, batch_id: int) -> None:
        self._emit(self.correlation_hits(batch), f"correlation-{batch_id}")

    def detectors(self, batch: DataFrame, batch_id: int) -> None:
        self._emit(self.detector_hits(batch), f"detectors-{batch_id}")

    def single_hits(self, batch: DataFrame) -> list[Hit]:
        rows = batch.select(
            "rule_id",
            "entity",
            "event_id",
            F.unix_micros("timestamp").alias("timestamp_us"),
            "source_ip",
            "user_name",
            "event_category",
            "event_outcome",
        ).collect()
        hits = []
        for row in rows:
            rule = self._rules.by_id(row["rule_id"])
            moment = from_micros(row["timestamp_us"])
            hits.append(
                Hit(
                    rule_id=rule.meta.id,
                    entity_type=entity_type(rule.entity_field),
                    entity=row["entity"],
                    first_seen=moment,
                    last_seen=moment,
                    detected_at=moment,
                    event_ids=frozenset({row["event_id"]}),
                    source_ip=row["source_ip"],
                    user_name=row["user_name"],
                    has_success=row["event_category"] == "authentication"
                    and row["event_outcome"] == "success",
                )
            )
        return hits

    def correlation_hits(self, batch: DataFrame) -> list[Hit]:
        hits = []
        for row in batch.collect():
            rule = self._rules.by_id(row["rule_id"])
            if not isinstance(rule, CorrelationRule):
                raise TypeError(f"{rule.meta.name} is not a correlation rule")
            entries = [
                WindowEntry(
                    from_micros(entry["timestamp_us"]),
                    entry["event_id"],
                    entry["reference"],
                    dict(entry["attributes"]),
                )
                for entry in row["entries"]
            ]
            hit = evaluate_window(rule, json.loads(row["group_key"]), entries)
            if hit is not None:
                hits.append(hit)
        return hits

    def detector_hits(self, batch: DataFrame) -> list[Hit]:
        rows = batch.withColumn("timestamp_us", F.unix_micros("timestamp")).collect()
        by_rule: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            event = event_dict(row)
            for rule_id in row["detector_rules"]:
                by_rule[rule_id].append(event)
        hits: list[Hit] = []
        with self._detector_lock:
            for rule_id, events in by_rule.items():
                rule = self._rules.by_id(rule_id)
                if not isinstance(rule, DetectorRule):
                    raise TypeError(f"{rule.meta.name} is not a detector rule")
                hits += DETECTORS[rule.detector](rule, events, self._state, self._geo)
            self._after_detectors()
        return hits


def event_dict(row: Row) -> dict[str, Any]:
    values = row.asDict()
    values["timestamp"] = from_micros(values.pop("timestamp_us"))
    values.pop("detector_rules", None)
    return values


def detector_events(events: DataFrame, rules: Sequence[DetectorRule]) -> DataFrame:
    matched = F.filter(
        F.array(
            *[F.when(compile_expression(rule.expression), F.lit(rule.meta.id)) for rule in rules]
        ),
        lambda item: item.isNotNull(),
    )
    return (
        events.withColumn("detector_rules", matched)
        .filter(F.size("detector_rules") > 0)
        .select(
            "event_id",
            "timestamp",
            "source_ip",
            "user_name",
            "event_action",
            "event_outcome",
            "event_category",
            "detector_rules",
        )
    )


def start_queries(
    events: DataFrame,
    rules: RuleSet,
    handler: DetectionHandler,
    settings: StreamingSettings,
    watermark: str,
    available_now: bool = False,
) -> list[StreamingQuery]:
    def configure(name: str, writer: DataStreamWriter) -> DataStreamWriter:
        writer = writer.queryName(f"{JOB_NAME}_{name}").option(
            "checkpointLocation", settings.checkpoint(JOB_NAME, name)
        )
        if available_now:
            return writer.trigger(availableNow=True)
        return writer.trigger(processingTime=settings.trigger_interval)

    queries = []
    if rules.single_event:
        matches = single_event_matches(events, rules.single_event)
        queries.append(
            configure("single", matches.writeStream.foreachBatch(handler.single)).start()
        )
    if rules.correlations:
        entries = correlation_entries(events, rules.correlations).withWatermark(
            "window_end", watermark
        )
        windows = aggregate_windows(entries)
        queries.append(
            configure(
                "correlation",
                windows.writeStream.outputMode("update").foreachBatch(handler.correlation),
            ).start()
        )
    if rules.detectors:
        selected = detector_events(events, rules.detectors)
        queries.append(
            configure("detectors", selected.writeStream.foreachBatch(handler.detectors)).start()
        )
    return queries


def _lookup_providers() -> list[LookupProvider]:
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    return [AbuseIpDbProvider(api_key)] if api_key else []


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = StreamingSettings()
    clickhouse = ClickHouseSettings()
    rules = load_rules()
    suppression = parse_duration(os.environ.get("ALERT_SUPPRESSION", "30m"))
    watermark = os.environ.get("DETECTION_WATERMARK", "10 minutes")
    client = connect(clickhouse, autogenerate_session_id=False)
    manager = AlertManager(rules, suppression)
    manager.restore(load_recent_alerts(client, suppression + timedelta(days=1)))
    intel = ThreatIntelService(ThreatIntelStore(client), lookups=_lookup_providers())
    enricher = AlertEnricher(
        ClickHouseGeoLookup(client),
        intel,
        ClickHouseBaselineLookup(connect(clickhouse, autogenerate_session_id=False)),
        load_weights(),
        recurrence_counter(manager),
    )
    producer = Producer({"bootstrap.servers": settings.kafka_bootstrap_servers, "linger.ms": 20})
    sink = AlertSink(enricher, client, producer, ALERTS_TOPIC)
    publish_lock = threading.Lock()

    def publish(alerts: list[Alert], token: str) -> None:
        with publish_lock:
            sink.publish(alerts, token)

    state = ClickHouseStateStore(connect(clickhouse, autogenerate_session_id=False))
    detector_geo = ClickHouseGeoLookup(connect(clickhouse, autogenerate_session_id=False))
    handler = DetectionHandler(rules, manager, publish, state, detector_geo, state.flush)
    spark: SparkSession = build_session("sentinelflow-detect", settings)
    spark.streams.addListener(QueryProgressRecorder(JOB_NAME))
    events = parse_events(read_kafka(spark, settings, subscribe_pattern=NORMALIZED_TOPIC))
    start_queries(events, rules, handler, settings, watermark)
    logger.info("started detection with %d alerting rules", len(rules.alerting))
    await_all(spark)


if __name__ == "__main__":
    main()
