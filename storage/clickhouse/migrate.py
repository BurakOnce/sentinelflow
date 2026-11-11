import re
import sys
import time
from pathlib import Path
from string import Template

from clickhouse_connect.driver.client import Client

from storage.clickhouse.client import ClickHouseSettings, connect

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
STATEMENT_SEPARATOR = re.compile(r";\s*(?:\n|$)")


def render(path: Path, settings: ClickHouseSettings) -> list[str]:
    text = Template(path.read_text(encoding="utf-8")).substitute(settings.template_values())
    return [statement.strip() for statement in STATEMENT_SEPARATOR.split(text) if statement.strip()]


def pending(client: Client, directory: Path = MIGRATIONS_DIR) -> list[Path]:
    client.command(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version String, applied_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY version"
    )
    applied = {row[0] for row in client.query("SELECT version FROM schema_migrations").result_rows}
    return [path for path in sorted(directory.glob("*.sql")) if path.stem not in applied]


def apply(
    client: Client, settings: ClickHouseSettings, directory: Path = MIGRATIONS_DIR
) -> list[str]:
    applied: list[str] = []
    for path in pending(client, directory):
        for statement in render(path, settings):
            client.command(statement)
        client.insert("schema_migrations", [[path.stem]], column_names=["version"])
        applied.append(path.stem)
    return applied


def wait_for(settings: ClickHouseSettings, attempts: int = 30) -> Client:
    for attempt in range(attempts):
        try:
            return connect(settings)
        except Exception:
            if attempt == attempts - 1:
                raise
            time.sleep(2)
    raise RuntimeError("unreachable")


def main() -> None:
    settings = ClickHouseSettings()
    applied = apply(wait_for(settings), settings)
    sys.stdout.write(f"applied migrations: {', '.join(applied) or 'none'}\n")


if __name__ == "__main__":
    main()
