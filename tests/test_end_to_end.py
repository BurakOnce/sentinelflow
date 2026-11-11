import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from simulator.simulation import AttackRequest, SimulationPlan, emit, simulate
from simulator.sinks import KafkaSink
from storage.clickhouse.client import ClickHouseSettings, connect

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_SECONDS = int(os.environ.get("E2E_TIMEOUT_SECONDS", "240"))


def environment_file() -> dict[str, str]:
    path = ROOT / ".env"
    if not path.exists():
        return {}
    lines = path.read_text(encoding="utf-8").splitlines()
    pairs = [line.split("=", 1) for line in lines if "=" in line and not line.startswith("#")]
    return {key.strip(): value.strip() for key, value in pairs}


def clickhouse_settings() -> ClickHouseSettings:
    values = environment_file()
    return ClickHouseSettings(
        host=os.environ.get("CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("CLICKHOUSE_PORT", values.get("CLICKHOUSE_HTTP_PORT", "8123"))),
        user=os.environ.get("CLICKHOUSE_USER", values.get("CLICKHOUSE_USER", "sentinel")),
        password=os.environ.get("CLICKHOUSE_PASSWORD", values.get("CLICKHOUSE_PASSWORD", "")),
        database=os.environ.get("CLICKHOUSE_DB", values.get("CLICKHOUSE_DB", "sentinelflow")),
    )


def test_port_scan_raises_enriched_alert_in_clickhouse() -> None:
    try:
        client = connect(clickhouse_settings())
        client.command("SELECT 1")
    except Exception as error:
        pytest.skip(f"stack is not running: {error}")
    end = datetime.now(UTC).replace(microsecond=0)
    plan = SimulationPlan(
        start=end - timedelta(minutes=10),
        end=end,
        seed=secrets.randbelow(1_000_000),
        users=20,
        attacks=(AttackRequest("port_scan", 0.1),),
        baseline=False,
    )
    records = list(simulate(plan))
    attacker = records[0].event.src_ip
    bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092")
    with KafkaSink.connect(bootstrap) as sink:
        stats = emit(records, sink)
    assert stats.labels == len(records)

    deadline = time.monotonic() + TIMEOUT_SECONDS
    alert = None
    while time.monotonic() < deadline:
        rows = client.query(
            "SELECT event_count, risk_score, country_code FROM alerts FINAL "
            "WHERE entity = {ip:String} AND rule_name = 'port_scan'",
            parameters={"ip": attacker},
        ).result_rows
        if rows:
            alert = rows[0]
            break
        time.sleep(5)

    assert alert is not None, f"no port_scan alert for {attacker} within {TIMEOUT_SECONDS}s"
    event_count, risk_score, country_code = alert
    assert event_count >= 20
    assert 0 < risk_score <= 100
    assert country_code
    events = client.query(
        "SELECT count() FROM events WHERE source_ip = toIPv4({ip:String})",
        parameters={"ip": attacker},
    ).result_rows[0][0]
    labels = client.query(
        "SELECT count() FROM ground_truth WHERE src_ip = {ip:String}", parameters={"ip": attacker}
    ).result_rows[0][0]
    assert events == len(records)
    assert labels == len(records)
