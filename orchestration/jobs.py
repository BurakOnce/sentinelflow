import os
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import dagster as dg

from enrichment.cli import feed_providers
from enrichment.geoip_loader import download_dbip, load_dbip, load_fixture
from enrichment.threat_intel import ThreatIntelService, ThreatIntelStore
from orchestration.lake import compact_day, expire_partitions, s3_location
from storage.clickhouse.client import connect


@dg.op
def refresh_threat_intel(context: dg.OpExecutionContext) -> None:
    names = os.environ.get("THREAT_INTEL_FEEDS", "fixture").split(",")
    service = ThreatIntelService(ThreatIntelStore(connect()), feeds=feed_providers(names))
    for name, count in service.refresh_feeds().items():
        context.log.info(f"{name}: {count} indicators")
        context.add_output_metadata({name: count})


@dg.op
def refresh_geoip(context: dg.OpExecutionContext) -> None:
    client = connect()
    if os.environ.get("GEOIP_SOURCE", "fixture") == "dbip":
        city_path, asn_path = download_dbip(Path("data/geoip"))
        cities, asns = load_dbip(client, city_path, asn_path)
    else:
        cities, asns = load_fixture(client)
    context.log.info(f"loaded {cities} city and {asns} asn networks")


@dg.op(config_schema={"day": dg.Field(str, is_required=False)})
def compact_silver(context: dg.OpExecutionContext) -> None:
    configured = context.op_config.get("day")
    day = date.fromisoformat(configured) if configured else datetime.now(UTC).date() - timedelta(1)
    written = compact_day(s3_location("silver"), s3_location("silver"), day)
    context.log.info(f"compacted {day}: {written}")


@dg.op
def expire_bronze(context: dg.OpExecutionContext) -> None:
    keep = int(os.environ.get("BRONZE_RETENTION_DAYS", "30"))
    removed = expire_partitions(
        s3_location("bronze"), "raw_logs", "ingest_date", keep, datetime.now(UTC).date()
    )
    context.log.info(f"removed {len(removed)} bronze partitions older than {keep} days")


@dg.job
def threat_intel_job() -> None:
    refresh_threat_intel()


@dg.job
def geoip_job() -> None:
    refresh_geoip()


@dg.job
def silver_compaction_job() -> None:
    compact_silver()


@dg.job
def bronze_retention_job() -> None:
    expire_bronze()
