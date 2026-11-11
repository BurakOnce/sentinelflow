import re
from pathlib import Path

import pytest
import yaml

from detections.catalog import SEED_PATH, render
from detections.engine.loader import load_rules
from storage.clickhouse.client import ClickHouseSettings
from storage.clickhouse.migrate import MIGRATIONS_DIR
from storage.clickhouse.migrate import render as render_migration
from streaming.alert_sink import ALERT_COLUMNS
from streaming.schema import EVENT_FIELD_NAMES, EVENT_FIELDS, NormalizedEvent, clickhouse_columns

ROOT = Path(__file__).resolve().parent.parent
COLUMN = re.compile(r"^\s+(?P<name>\w+) (?P<type>.+?)(?: CODEC\(.*\))?,?$")


def table_columns(table: str) -> list[tuple[str, str]]:
    columns: list[tuple[str, str]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        for statement in render_migration(path, ClickHouseSettings(user="reader", password="")):
            header = f"CREATE TABLE IF NOT EXISTS {table}\n"
            if statement.startswith(header):
                body = statement[len(header) :].split("\n)\n", 1)[0]
                for line in body.splitlines()[1:]:
                    match = COLUMN.match(line)
                    if match and not line.strip().startswith("INDEX"):
                        columns.append((match["name"], match["type"]))
            alter = re.findall(r"ADD COLUMN IF NOT EXISTS (\w+) ([^,;]+?) AFTER", statement)
            if statement.startswith(f"ALTER TABLE {table}"):
                columns.extend(alter)
    return columns


def test_clickhouse_events_table_matches_schema() -> None:
    assert table_columns("events") == clickhouse_columns()


def test_dbt_source_matches_schema() -> None:
    sources = yaml.safe_load((ROOT / "transform/models/sources.yml").read_text(encoding="utf-8"))
    table = next(table for table in sources["sources"][0]["tables"] if table["name"] == "events")
    documented = [(column["name"], column["data_type"]) for column in table["columns"]]
    assert documented == clickhouse_columns()
    descriptions = {column["name"]: column["description"] for column in table["columns"]}
    assert descriptions == {field.name: field.description for field in EVENT_FIELDS}


def test_python_event_matches_schema() -> None:
    assert tuple(NormalizedEvent.__dataclass_fields__) == EVENT_FIELD_NAMES


def test_spark_schema_matches_schema() -> None:
    pytest.importorskip("pyspark")
    from streaming.schema import spark_schema

    schema = spark_schema()
    assert tuple(schema.fieldNames()) == EVENT_FIELD_NAMES
    assert [field.nullable for field in schema.fields] == [field.nullable for field in EVENT_FIELDS]


def test_alert_sink_columns_exist_in_clickhouse() -> None:
    names = [name for name, _ in table_columns("alerts")]
    assert set(ALERT_COLUMNS) <= set(names)


def test_rule_catalog_seed_is_current() -> None:
    assert SEED_PATH.read_text(encoding="utf-8") == render(load_rules())
