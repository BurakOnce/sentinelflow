import json
import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from clickhouse_connect.driver.client import Client

from detections.engine.alerts import Alert, AlertManager
from detections.engine.detectors import MemoryStateStore
from enrichment.alert_enrichment import AlertContext, AlertEnricher, RecurrenceCounter
from storage.clickhouse.client import insert_rows

ALERT_COLUMNS = (
    "alert_id",
    "rule_id",
    "rule_name",
    "rule_title",
    "rule_type",
    "level",
    "mitre_tactics",
    "mitre_techniques",
    "entity_type",
    "entity",
    "source_ip",
    "user_name",
    "first_seen",
    "last_seen",
    "detected_at",
    "event_count",
    "sample_event_ids",
    "event_ids",
    "status",
    "created_at",
    "updated_at",
    "country_code",
    "country",
    "city",
    "asn",
    "as_org",
    "is_known_malicious",
    "abuse_score",
    "risk_score",
    "risk_factors",
)
logger = logging.getLogger(__name__)


class MessageProducer(Protocol):
    def produce(self, topic: str, value: bytes, key: bytes | None = None) -> None: ...

    def flush(self, timeout: float) -> int: ...


def alert_row(alert: Alert, context: AlertContext) -> list[Any]:
    return [
        alert.alert_id,
        alert.rule_id,
        alert.rule_name,
        alert.rule_title,
        alert.rule_type,
        alert.level,
        list(alert.mitre_tactics),
        list(alert.mitre_techniques),
        alert.entity_type,
        alert.entity,
        alert.source_ip,
        alert.user_name,
        alert.first_seen,
        alert.last_seen,
        alert.detected_at,
        alert.event_count,
        alert.sample_event_ids,
        list(alert.event_ids),
        alert.status,
        alert.created_at,
        alert.updated_at,
        context.country_code,
        context.country,
        context.city,
        context.asn,
        context.as_org,
        int(context.is_known_malicious),
        context.abuse_score,
        context.risk.value,
        context.risk.factors,
    ]


def alert_message(alert: Alert, context: AlertContext) -> dict[str, Any]:
    message = dict(zip(ALERT_COLUMNS, alert_row(alert, context), strict=True))
    message.pop("event_ids")
    return {
        key: value.isoformat() if isinstance(value, datetime) else value
        for key, value in message.items()
    }


class AlertSink:
    def __init__(
        self,
        enricher: AlertEnricher,
        client: Client,
        producer: MessageProducer | None,
        topic: str,
    ) -> None:
        self._enricher = enricher
        self._client = client
        self._producer = producer
        self._topic = topic

    def publish(self, alerts: Sequence[Alert], token: str) -> None:
        if not alerts:
            return
        enriched = self._enricher.enrich(alerts)
        rows = [alert_row(alert, context) for alert, context in enriched]
        insert_rows(self._client, "alerts", ALERT_COLUMNS, rows, deduplication_token=token)
        if self._producer is None:
            return
        for alert, context in enriched:
            self._producer.produce(
                self._topic,
                json.dumps(alert_message(alert, context)).encode("utf-8"),
                alert.alert_id.encode("utf-8"),
            )
        self._producer.flush(10.0)


RESTORE_FIELDS = (
    "alert_id",
    "rule_id",
    "rule_name",
    "rule_title",
    "rule_type",
    "level",
    "mitre_tactics",
    "mitre_techniques",
    "entity_type",
    "entity",
    "first_seen",
    "last_seen",
    "detected_at",
    "event_ids",
    "event_count",
    "status",
    "created_at",
    "updated_at",
)
RESTORE_QUERY = """
SELECT
    alert_id, rule_id, rule_name, rule_title, rule_type, level, mitre_tactics, mitre_techniques,
    entity_type, entity, first_seen, last_seen, detected_at, event_ids, event_count, status,
    created_at, updated_at
FROM alerts FINAL
WHERE last_seen >= (SELECT max(last_seen) FROM alerts) - toIntervalSecond({seconds:UInt32})
"""


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def load_recent_alerts(client: Client, lookback: timedelta) -> list[Alert]:
    result = client.query(RESTORE_QUERY, parameters={"seconds": int(lookback.total_seconds())})
    alerts = []
    for row in result.result_rows:
        values = dict(zip(RESTORE_FIELDS, row, strict=True))
        ids = dict.fromkeys(values["event_ids"])
        alerts.append(
            Alert(
                alert_id=values["alert_id"],
                rule_id=values["rule_id"],
                rule_name=values["rule_name"],
                rule_title=values["rule_title"],
                rule_type=values["rule_type"],
                level=values["level"],
                mitre_tactics=tuple(values["mitre_tactics"]),
                mitre_techniques=tuple(values["mitre_techniques"]),
                entity_type=values["entity_type"],
                entity=values["entity"],
                first_seen=_utc(values["first_seen"]),
                last_seen=_utc(values["last_seen"]),
                detected_at=_utc(values["detected_at"]),
                event_ids=ids,
                overflow_count=max(values["event_count"] - len(ids), 0),
                status=values["status"],
                created_at=_utc(values["created_at"]),
                updated_at=_utc(values["updated_at"]),
            )
        )
    return alerts


def recurrence_counter(manager: AlertManager) -> RecurrenceCounter:
    def count(entity_type: str, entity: str, since: datetime) -> int:
        return manager.recent_alerts(entity_type, entity, since)

    return count


class ClickHouseStateStore(MemoryStateStore):
    def __init__(self, client: Client) -> None:
        super().__init__()
        self._client = client
        self._dirty: set[tuple[str, str]] = set()
        result = client.query("SELECT detector, key, value FROM detector_state FINAL")
        for detector, key, value in result.result_rows:
            self.values[(detector, key)] = json.loads(value)

    def put(self, detector: str, key: str, value: dict[str, Any]) -> None:
        super().put(detector, key, value)
        self._dirty.add((detector, key))

    def flush(self) -> None:
        if not self._dirty:
            return
        now = datetime.now(UTC)
        rows = [
            [detector, key, json.dumps(self.values[(detector, key)]), now]
            for detector, key in sorted(self._dirty)
        ]
        insert_rows(
            self._client, "detector_state", ("detector", "key", "value", "updated_at"), rows
        )
        self._dirty.clear()
