import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from enrichment.geoip_loader import download_dbip, load_dbip, load_fixture, loaded_source
from enrichment.threat_intel import (
    BlocklistFeedProvider,
    FeedProvider,
    FixtureProvider,
    ThreatIntelService,
    ThreatIntelStore,
)
from storage.clickhouse.client import ClickHouseSettings
from storage.clickhouse.migrate import apply, wait_for

app = typer.Typer(no_args_is_help=True, add_completion=False, help="SentinelFlow enrichment")


class GeoSource(StrEnum):
    FIXTURE = "fixture"
    DBIP = "dbip"


def feed_providers(names: list[str]) -> list[FeedProvider]:
    available: dict[str, FeedProvider] = {
        "fixture": FixtureProvider(),
        "firehol": BlocklistFeedProvider(),
    }
    unknown = sorted(set(names) - set(available))
    if unknown:
        raise typer.BadParameter(f"unknown feeds: {', '.join(unknown)}", param_hint="--feed")
    return [available[name] for name in names]


@app.command()
def geoip(
    source: Annotated[GeoSource, typer.Option(help="Offline fixture or DB-IP Lite")] = (
        GeoSource.FIXTURE
    ),
    month: Annotated[str | None, typer.Option(help="DB-IP release as YYYY-MM")] = None,
    directory: Annotated[Path, typer.Option(help="Download directory")] = Path("data/geoip"),
) -> None:
    client = wait_for(ClickHouseSettings())
    if source is GeoSource.FIXTURE:
        cities, asns = load_fixture(client)
    else:
        city_path, asn_path = download_dbip(directory, month)
        cities, asns = load_dbip(client, city_path, asn_path)
    typer.echo(f"loaded {cities} city networks and {asns} asn networks from {source}")


@app.command()
def intel(
    feed: Annotated[
        list[str] | None, typer.Option(help="Feed to refresh: fixture, firehol")
    ] = None,
) -> None:
    names = feed or os.environ.get("THREAT_INTEL_FEEDS", "fixture").split(",")
    service = ThreatIntelService(
        ThreatIntelStore(wait_for(ClickHouseSettings())), feeds=feed_providers(names)
    )
    for name, count in service.refresh_feeds().items():
        typer.echo(f"{name}: {count} indicators")


@app.command()
def bootstrap() -> None:
    settings = ClickHouseSettings()
    client = wait_for(settings)
    applied = apply(client, settings)
    typer.echo(f"applied migrations: {', '.join(applied) or 'none'}")
    if loaded_source(client) is None:
        cities, asns = load_fixture(client)
        typer.echo(f"loaded fixture geoip: {cities} city and {asns} asn networks")
    names = os.environ.get("THREAT_INTEL_FEEDS", "fixture").split(",")
    service = ThreatIntelService(ThreatIntelStore(client), feeds=feed_providers(names))
    for name, count in service.refresh_feeds().items():
        typer.echo(f"threat intel {name}: {count} indicators")


if __name__ == "__main__":
    app()
