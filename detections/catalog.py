import csv
import io
import sys
from pathlib import Path

import typer

from detections.engine.alerts import rule_type
from detections.engine.fixtures import missing_positive_fixtures, run_fixtures
from detections.engine.loader import RuleSet, load_rules
from enrichment.geo import NetworkTableGeoLookup

SEED_PATH = Path(__file__).resolve().parent.parent / "transform" / "seeds" / "rule_catalog.csv"
COLUMNS = (
    "rule_id",
    "rule_name",
    "rule_title",
    "rule_type",
    "level",
    "status",
    "techniques",
    "tactics",
    "source_file",
)
app = typer.Typer(add_completion=False, help="Detection rule catalogue")


def render(rules: RuleSet) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for rule in sorted(rules.alerting, key=lambda item: item.meta.name):
        writer.writerow(
            [
                rule.meta.id,
                rule.meta.name,
                rule.meta.title,
                rule_type(rule),
                rule.meta.level,
                rule.meta.status,
                "|".join(rule.meta.techniques),
                "|".join(rule.meta.tactics),
                rule.meta.path.name if rule.meta.path else "",
            ]
        )
    return buffer.getvalue()


@app.command()
def validate() -> None:
    rules = load_rules()
    typer.echo(f"{len(rules.rules)} rules loaded, {len(rules.alerting)} alerting")
    for rule in sorted(rules.alerting, key=lambda item: item.meta.name):
        typer.echo(f"  {rule.meta.name:<24}{rule_type(rule):<13}{', '.join(rule.meta.techniques)}")
    results = run_fixtures(rules, NetworkTableGeoLookup.from_fixtures())
    for result in results:
        status = "ok  " if result.passed else "FAIL"
        typer.echo(f"  {status} {result.rule:<22}{result.expected:<10}{result.case}")
    missing = missing_positive_fixtures(rules, results)
    for name in missing:
        typer.echo(f"  FAIL {name} has no positive fixture", err=True)
    if missing or not all(result.passed for result in results):
        raise typer.Exit(1)
    typer.echo(f"{len(results)} fixture cases passed")


@app.command()
def export(output: Path = SEED_PATH, check: bool = False) -> None:
    content = render(load_rules())
    if check:
        current = output.read_text(encoding="utf-8") if output.exists() else ""
        if current != content:
            typer.echo(f"{output} is out of date, run the export without --check", err=True)
            raise typer.Exit(1)
        typer.echo(f"{output} is up to date")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8", newline="\n")
    sys.stdout.write(f"wrote {output}\n")


if __name__ == "__main__":
    app()
