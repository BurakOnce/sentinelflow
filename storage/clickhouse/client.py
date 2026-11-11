import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.client import Client


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True, slots=True)
class ClickHouseSettings:
    host: str = field(default_factory=lambda: _env("CLICKHOUSE_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(_env("CLICKHOUSE_PORT", "8123")))
    user: str = field(default_factory=lambda: _env("CLICKHOUSE_USER", "sentinel"))
    password: str = field(default_factory=lambda: _env("CLICKHOUSE_PASSWORD", ""))
    database: str = field(default_factory=lambda: _env("CLICKHOUSE_DB", "sentinelflow"))
    kafka_brokers: str = field(
        default_factory=lambda: _env("CLICKHOUSE_KAFKA_BROKERS", "redpanda:9092")
    )

    def template_values(self) -> dict[str, str]:
        return {
            "CLICKHOUSE_USER": self.user,
            "CLICKHOUSE_PASSWORD": self.password,
            "CLICKHOUSE_DB": self.database,
            "KAFKA_BROKERS": self.kafka_brokers,
        }


def connect(settings: ClickHouseSettings | None = None, **overrides: Any) -> Client:
    config = settings or ClickHouseSettings()
    return clickhouse_connect.get_client(
        host=config.host,
        port=config.port,
        username=config.user,
        password=config.password,
        database=config.database,
        **overrides,
    )


def insert_rows(
    client: Client,
    table: str,
    columns: Sequence[str],
    rows: Sequence[Sequence[Any]],
    deduplication_token: str | None = None,
) -> None:
    if not rows:
        return
    settings = {"insert_deduplication_token": deduplication_token} if deduplication_token else {}
    client.insert(table, list(rows), column_names=list(columns), settings=settings)
