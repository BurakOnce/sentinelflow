from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyspark.sql.types import DataType, StructType


class FieldType(StrEnum):
    STRING = "string"
    UINT16 = "uint16"
    TIMESTAMP = "timestamp"
    IPV4 = "ipv4"


@dataclass(frozen=True, slots=True)
class SchemaField:
    name: str
    type: FieldType
    nullable: bool
    description: str
    low_cardinality: bool = False

    @property
    def clickhouse_type(self) -> str:
        base = {
            FieldType.STRING: "String",
            FieldType.UINT16: "UInt16",
            FieldType.TIMESTAMP: "DateTime64(6, 'UTC')",
            FieldType.IPV4: "IPv4",
        }[self.type]
        if self.nullable:
            base = f"Nullable({base})"
        return f"LowCardinality({base})" if self.low_cardinality else base

    def spark_type(self) -> DataType:
        from pyspark.sql.types import IntegerType, StringType, TimestampType

        if self.type is FieldType.UINT16:
            return IntegerType()
        if self.type is FieldType.TIMESTAMP:
            return TimestampType()
        return StringType()


EVENT_FIELDS: tuple[SchemaField, ...] = (
    SchemaField("event_id", FieldType.STRING, False, "SHA-256 of the raw message"),
    SchemaField("timestamp", FieldType.TIMESTAMP, False, "Event time parsed from the log line"),
    SchemaField("ingest_time", FieldType.TIMESTAMP, False, "Time the broker received the line"),
    SchemaField("source_type", FieldType.STRING, False, "nginx, ssh, firewall or app", True),
    SchemaField("event_category", FieldType.STRING, False, "authentication, network or web", True),
    SchemaField("event_action", FieldType.STRING, False, "Normalized action name", True),
    SchemaField("event_outcome", FieldType.STRING, True, "success or failure", True),
    SchemaField("source_ip", FieldType.IPV4, True, "Client or packet source address"),
    SchemaField("source_port", FieldType.UINT16, True, "Client or packet source port"),
    SchemaField("destination_ip", FieldType.IPV4, True, "Packet destination address"),
    SchemaField("destination_port", FieldType.UINT16, True, "Packet destination port"),
    SchemaField("host_name", FieldType.STRING, True, "Host or service that emitted the line", True),
    SchemaField("user_name", FieldType.STRING, True, "Account name presented by the client"),
    SchemaField("user_agent", FieldType.STRING, True, "HTTP user agent"),
    SchemaField("http_method", FieldType.STRING, True, "HTTP request method", True),
    SchemaField("url_path", FieldType.STRING, True, "Request path including the query string"),
    SchemaField("http_status", FieldType.UINT16, True, "HTTP response status"),
    SchemaField("raw_message", FieldType.STRING, False, "Original log line"),
)
EVENT_FIELD_NAMES: tuple[str, ...] = tuple(field.name for field in EVENT_FIELDS)


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    ingest_time: datetime
    source_type: str
    event_category: str
    event_action: str
    event_outcome: str | None
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    host_name: str | None
    user_name: str | None
    user_agent: str | None
    http_method: str | None
    url_path: str | None
    http_status: int | None
    raw_message: str

    def as_dict(self) -> dict[str, object]:
        return {field.name: getattr(self, field.name) for field in fields(self)}


def spark_schema() -> StructType:
    from pyspark.sql.types import StructField, StructType

    return StructType(
        [StructField(field.name, field.spark_type(), field.nullable) for field in EVENT_FIELDS]
    )


def clickhouse_columns() -> list[tuple[str, str]]:
    return [(field.name, field.clickhouse_type) for field in EVENT_FIELDS]
