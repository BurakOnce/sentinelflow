import os
import subprocess
import time
from collections.abc import Sequence
from typing import Annotated

import typer
from clickhouse_connect.driver.client import Client

from orchestration.dbt import PROJECT_DIR
from storage.clickhouse.client import connect

app = typer.Typer(add_completion=False, help="Demo helpers")
LINKS = (
    ("Grafana", "GRAFANA_URL", "http://localhost:3000"),
    ("Mailpit", "MAILPIT_URL", "http://localhost:8025"),
    ("Dagster", "DAGSTER_URL", "http://localhost:3001"),
    ("Redpanda Console", "REDPANDA_CONSOLE_URL", "http://localhost:8080"),
)
PROGRESS_QUERY = """
SELECT
    (SELECT count() FROM events),
    (SELECT count() FROM ground_truth),
    (SELECT count() FROM alerts),
    (SELECT max(offsets_behind_latest) FROM pipeline_batches
     WHERE processed_at > now() - INTERVAL 1 MINUTE)
"""


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    cells = [[str(value) for value in row] for row in rows]
    widths = [
        max(len(str(item)) for item in column) for column in zip(headers, *cells, strict=False)
    ]
    line = "  ".join(f"{{:<{width}}}" for width in widths)
    return "\n".join(
        [line.format(*headers), line.format(*("-" * width for width in widths))]
        + [line.format(*row) for row in cells]
    )


def wait_until_idle(
    client: Client, stable_checks: int = 3, interval: float = 10, limit: int = 90
) -> None:
    previous = None
    stable = 0
    for _ in range(limit):
        events, labels, alerts, lag = client.query(PROGRESS_QUERY).result_rows[0]
        current = (events, labels, alerts)
        idle = events > 0 and (lag or 0) == 0 and current == previous
        stable = stable + 1 if idle else 0
        typer.echo(f"  events={events} labels={labels} alert_versions={alerts} lag={lag or 0}")
        if stable >= stable_checks:
            return
        previous = current
        time.sleep(interval)
    typer.echo("  pipeline did not settle, continuing with current data")


def build_models() -> None:
    result = subprocess.run(
        ["dbt", "build", "--profiles-dir", str(PROJECT_DIR), "--project-dir", str(PROJECT_DIR)],
        capture_output=True,
        text=True,
        check=False,
    )
    summary = [line for line in result.stdout.splitlines() if "Done." in line]
    typer.echo(f"  dbt: {summary[-1].split('Done.')[-1].strip() if summary else 'no summary'}")
    if result.returncode != 0:
        typer.echo(result.stdout[-2000:], err=True)


def print_summary(client: Client) -> None:
    events = client.query(
        "SELECT source_type, count() FROM events GROUP BY source_type ORDER BY source_type"
    ).result_rows
    levels = client.query(
        "SELECT level, count() FROM alerts FINAL GROUP BY level "
        "ORDER BY indexOf(['critical', 'high', 'medium', 'low', 'informational'], level)"
    ).result_rows
    efficacy = client.query(
        "SELECT rule_name, alerts, true_positives, false_positives, false_negatives, "
        "round(precision, 3), round(recall, 3), round(avg_detection_latency_seconds, 1) "
        "FROM analytics.fct_detection_efficacy ORDER BY rule_name"
    ).result_rows
    failures = client.query("SELECT count() FROM parse_failures").result_rows[0][0]
    typer.echo("")
    by_source = ", ".join(f"{source} {count}" for source, count in events)
    by_level = ", ".join(f"{level} {count}" for level, count in levels)
    typer.echo(
        f"Events: {sum(count for _, count in events)} ({by_source}), dead letters: {failures}"
    )
    typer.echo(f"Alerts: {sum(count for _, count in levels)} ({by_level})")
    typer.echo("")
    typer.echo(
        _table(
            ("rule", "alerts", "tp", "fp", "fn", "precision", "recall", "latency_s"),
            [["-" if value is None else value for value in row] for row in efficacy],
        )
    )
    typer.echo("")
    for name, variable, default in LINKS:
        typer.echo(f"{name + ':':<18}{os.environ.get(variable, default)}")


@app.command()
def summary(wait: Annotated[bool, typer.Option(help="Wait for the pipeline first")] = True) -> None:
    client = connect()
    if wait:
        typer.echo("Waiting for the pipeline to drain")
        wait_until_idle(client)
    typer.echo("Building dbt models")
    build_models()
    print_summary(client)


if __name__ == "__main__":
    app()
