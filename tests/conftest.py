import os
import shutil
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from simulator.population import User, build_population
from simulator.records import LogRecord
from simulator.simulation import AttackRequest, SimulationPlan, simulate

if TYPE_CHECKING:
    from pyspark.sql import SparkSession

SIMULATION_START = datetime(2026, 9, 28, tzinfo=UTC)


@pytest.fixture(scope="session")
def population() -> tuple[User, ...]:
    return build_population(seed=11, size=200)


@pytest.fixture(scope="session")
def run_scenario() -> Callable[..., list[LogRecord]]:
    def run(name: str, intensity: float = 1.0, seed: int = 11) -> list[LogRecord]:
        plan = SimulationPlan(
            start=SIMULATION_START,
            end=SIMULATION_START + timedelta(hours=6),
            seed=seed,
            attacks=(AttackRequest(name, intensity),),
            baseline=False,
        )
        return list(simulate(plan))

    return run


def _java_available() -> bool:
    return shutil.which("java") is not None or bool(os.environ.get("JAVA_HOME"))


FILESYSTEM_SPARK = os.name != "nt" or bool(os.environ.get("HADOOP_HOME"))
requires_spark_filesystem = pytest.mark.skipif(
    not FILESYSTEM_SPARK, reason="spark file sinks need HADOOP_HOME on windows"
)


@pytest.fixture(scope="session")
def spark() -> Iterator["SparkSession"]:
    if not _java_available():
        pytest.skip("java is required for spark tests")
    pyspark_sql = pytest.importorskip("pyspark.sql")
    session = (
        pyspark_sql.SparkSession.builder.master("local[2]")
        .appName("sentinelflow-tests")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.shuffle.partitions", "2")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.streaming.stateStore.stateSchemaCheck", "false")
        .getOrCreate()
    )
    yield session
    session.stop()
