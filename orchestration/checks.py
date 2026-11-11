from collections.abc import Sequence

import dagster as dg

from storage.clickhouse.client import connect

EVENTS = dg.AssetKey(["sentinelflow", "events"])
ALERTS = dg.AssetKey(["sentinelflow", "alerts"])
PARSE_FAILURES = dg.AssetKey(["sentinelflow", "parse_failures"])
source_tables = [
    dg.AssetSpec(key, group_name="streaming", description=description)
    for key, description in (
        (EVENTS, "Normalized events written by the normalize job"),
        (ALERTS, "Alerts written by the detect job"),
        (PARSE_FAILURES, "Lines rejected by the parsers"),
        (dg.AssetKey(["sentinelflow", "ground_truth"]), "Simulator attack labels"),
    )
]


def _scalar(query: str) -> float:
    rows: Sequence[Sequence[float]] = connect().query(query).result_rows
    return float(rows[0][0]) if rows and rows[0][0] is not None else 0.0


@dg.asset_check(asset=EVENTS, description="Events arrived within the last hour of event time")
def events_are_fresh() -> dg.AssetCheckResult:
    lag = _scalar("SELECT dateDiff('second', max(ingest_time), now64()) FROM events")
    return dg.AssetCheckResult(
        passed=lag < 3600,
        metadata={"seconds_since_last_ingest": lag},
        severity=dg.AssetCheckSeverity.WARN,
    )


@dg.asset_check(asset=PARSE_FAILURES, description="Less than one percent of lines fail to parse")
def parse_failure_rate_is_low() -> dg.AssetCheckResult:
    failures = _scalar("SELECT count() FROM parse_failures")
    events = _scalar("SELECT count() FROM events")
    rate = failures / (failures + events) if failures + events else 0.0
    return dg.AssetCheckResult(passed=rate < 0.01, metadata={"failure_rate": rate})


@dg.asset_check(asset=ALERTS, description="Alert risk scores and counts are within range")
def alerts_are_well_formed() -> dg.AssetCheckResult:
    invalid = _scalar(
        "SELECT count() FROM alerts FINAL "
        "WHERE risk_score > 100 OR event_count = 0 OR last_seen < first_seen"
    )
    return dg.AssetCheckResult(passed=invalid == 0, metadata={"invalid_alerts": invalid})


@dg.asset_check(asset=EVENTS, description="Event ids are unique after deduplication")
def event_ids_are_unique() -> dg.AssetCheckResult:
    duplicates = _scalar(
        "SELECT count() - uniqExact(event_id) FROM events FINAL "
        "WHERE timestamp > now() - INTERVAL 1 DAY"
    )
    return dg.AssetCheckResult(passed=duplicates == 0, metadata={"duplicates": duplicates})


asset_checks = [
    events_are_fresh,
    parse_failure_rate_is_low,
    alerts_are_well_formed,
    event_ids_are_unique,
]
