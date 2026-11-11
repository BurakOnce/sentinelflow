from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from detection_support import scenario_events

from detections.engine.alerts import Alert, AlertManager
from detections.engine.detectors import MemoryStateStore
from detections.engine.loader import RuleSet, load_rules
from detections.engine.python_backend import correlation_hits, single_event_hits
from detections.engine.runner import evaluate
from enrichment.geo import NetworkTableGeoLookup
from streaming.schema import EVENT_FIELD_NAMES, spark_schema

if TYPE_CHECKING:
    from pyspark.sql import DataFrame, SparkSession

pytestmark = pytest.mark.spark
GEO = NetworkTableGeoLookup.from_fixtures()
SCENARIOS = [
    "ssh_bruteforce",
    "password_spraying",
    "brute_force_success",
    "port_scan",
    "web_attack",
]


@pytest.fixture(scope="module")
def rules() -> RuleSet:
    return load_rules()


@pytest.fixture(scope="module")
def events() -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for index, name in enumerate([*SCENARIOS, "credential_stuffing", "impossible_travel"]):
        collected += scenario_events(name, seed=20 + index)
    collected += scenario_events("", seed=5, baseline=True)[:4000]
    return collected


@pytest.fixture(scope="module")
def frame(spark: "SparkSession", events: list[dict[str, Any]]) -> "DataFrame":
    rows = [tuple(event[name] for name in EVENT_FIELD_NAMES) for event in events]
    return spark.createDataFrame(rows, spark_schema()).cache()


def test_single_event_rules_match_like_python(
    rules: RuleSet, events: list[dict[str, Any]], frame: "DataFrame"
) -> None:
    from detections.engine.spark_backend import single_event_matches

    spark_pairs = {
        (row["rule_id"], row["event_id"], row["entity"])
        for row in single_event_matches(frame, rules.single_event).collect()
    }
    python_pairs = {
        (hit.rule_id, next(iter(hit.event_ids)), hit.entity)
        for rule in rules.single_event
        for hit in single_event_hits(rule, events)
    }
    assert spark_pairs == python_pairs
    assert python_pairs


def test_correlation_windows_match_python_reference(
    rules: RuleSet, events: list[dict[str, Any]], frame: "DataFrame"
) -> None:
    from detections.engine.spark_backend import aggregate_windows, correlation_entries
    from streaming.detect_job import DetectionHandler

    handler = DetectionHandler(
        rules,
        AlertManager(rules, timedelta(minutes=30)),
        lambda alerts, token: None,
        MemoryStateStore(),
        GEO,
    )
    windows = aggregate_windows(correlation_entries(frame, rules.correlations))
    spark_hits = handler.correlation_hits(windows)
    python_hits = [hit for rule in rules.correlations for hit in correlation_hits(rule, events)]
    assert sorted(spark_hits, key=repr) == sorted(python_hits, key=repr)
    assert {hit.rule_id for hit in python_hits} == {rule.meta.id for rule in rules.correlations}


def test_handler_produces_same_alerts_as_python_runner(
    rules: RuleSet, events: list[dict[str, Any]], frame: "DataFrame"
) -> None:
    from detections.engine.spark_backend import (
        aggregate_windows,
        correlation_entries,
        single_event_matches,
    )
    from streaming.detect_job import DetectionHandler, detector_events

    manager = AlertManager(rules, timedelta(minutes=30))
    handler = DetectionHandler(rules, manager, lambda alerts, token: None, MemoryStateStore(), GEO)
    handler.single(single_event_matches(frame, rules.single_event), 0)
    handler.correlation(aggregate_windows(correlation_entries(frame, rules.correlations)), 0)
    handler.detectors(detector_events(frame, rules.detectors), 0)

    def summary(alerts: list[Alert]) -> set[tuple[str, str, int]]:
        return {(alert.rule_name, alert.entity, alert.event_count) for alert in alerts}

    expected = summary(evaluate(rules, events, GEO))
    assert summary(manager.open_alerts()) == expected
    assert {name for name, _, _ in expected} >= {"port_scan", "web_attack_pattern"}
