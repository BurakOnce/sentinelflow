from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from detections.engine.errors import RuleError
from detections.engine.expressions import (
    AllOf,
    AnyOf,
    FieldMatch,
    Negation,
    Operator,
    compile_detection,
)
from detections.engine.hits import window_starts
from detections.engine.loader import build_rule, load_rules
from detections.engine.model import CorrelationRule, CorrelationType, SingleEventRule
from detections.engine.python_backend import matches

EVENT: dict[str, Any] = {
    "event_action": "ssh_login",
    "event_outcome": "failure",
    "user_name": "Admin",
    "url_path": "/Search?q=UNION%20select",
    "source_ip": "10.20.0.5",
    "destination_port": 3389,
    "user_agent": None,
}
VALID_RULE: dict[str, Any] = {
    "title": "Test Rule",
    "id": "0b4c0a55-3c1b-4b8e-9c7e-2f6c1d9a7e11",
    "name": "test_rule",
    "status": "test",
    "description": "A rule used by the compiler tests.",
    "tags": ["attack.t1110"],
    "detection": {"selection": {"event_outcome": "failure"}, "condition": "selection"},
    "level": "low",
}


def check(detection: dict[str, Any], event: dict[str, Any] = EVENT) -> bool:
    return matches(compile_detection(detection, "test"), event)


def test_selection_fields_are_and_combined() -> None:
    expression = compile_detection(
        {
            "selection": {"event_action": "ssh_login", "event_outcome": "failure"},
            "condition": "selection",
        },
        "test",
    )
    assert expression == AllOf(
        (
            FieldMatch("event_action", Operator.EQUALS, ("ssh_login",)),
            FieldMatch("event_outcome", Operator.EQUALS, ("failure",)),
        )
    )


def test_value_lists_are_or_combined_unless_all_modifier() -> None:
    assert check({"s": {"user_name": ["root", "admin"]}, "condition": "s"})
    assert not check({"s": {"url_path|contains|all": ["union", "drop"]}, "condition": "s"})
    assert check({"s": {"url_path|contains|all": ["union", "select"]}, "condition": "s"})


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("user_name", "admin", True),
        ("url_path|contains", "union%20SELECT", True),
        ("url_path|startswith", "/search", True),
        ("url_path|endswith", "select", True),
        ("url_path|re", r"UNION%20s", True),
        ("url_path|re", r"union%20s", False),
        ("user_name", "ad*", True),
        ("user_name", "a?min", True),
        ("user_name", "adm", False),
        ("source_ip|cidr", "10.0.0.0/8", True),
        ("source_ip|cidr", "192.168.0.0/16", False),
        ("destination_port|gte", 1024, True),
        ("destination_port|lt", 1024, False),
        ("destination_port", 3389, True),
        ("user_agent", None, True),
        ("user_name", None, False),
    ],
)
def test_modifiers(key: str, value: Any, expected: bool) -> None:
    assert check({"s": {key: value}, "condition": "s"}) is expected


def test_condition_grammar_supports_boolean_operators_and_quantifiers() -> None:
    detection = {
        "sel_a": {"event_action": "ssh_login"},
        "sel_b": {"user_name": "nobody"},
        "filter": {"source_ip|cidr": "10.0.0.0/8"},
        "condition": "(1 of sel_* and not filter) or all of sel_*",
    }
    expression = compile_detection(detection, "test")
    assert isinstance(expression, AnyOf)
    assert isinstance(expression.children[0], AllOf)
    assert isinstance(expression.children[0].children[1], Negation)
    assert not matches(expression, EVENT)
    assert matches(expression, EVENT | {"source_ip": "36.1.1.1"})


def test_selection_list_of_maps_is_or() -> None:
    detection = {"s": [{"user_name": "root"}, {"user_name": "admin"}], "condition": "s"}
    assert check(detection)


@pytest.mark.parametrize(
    ("detection", "message"),
    [
        ({"s": {"unknown_field": 1}, "condition": "s"}, "unknown field"),
        ({"s": {"user_name|base64": "x"}, "condition": "s"}, "unsupported modifier"),
        ({"s": {"user_name|gt": 3}, "condition": "s"}, "needs a numeric field"),
        ({"s": {"destination_port|contains": "3"}, "condition": "s"}, "needs a text field"),
        ({"s": {"destination_port": "ssh"}, "condition": "s"}, "is not a number"),
        ({"s": {"user_name|re": "("}, "condition": "s"}, "invalid regular expression"),
        ({"s": {"user_name": "x"}, "condition": "t"}, "unknown selection"),
        ({"s": {"user_name": "x"}, "condition": "s and"}, "ended unexpectedly"),
        ({"s": {"user_name": "x"}, "condition": "(s"}, "condition ended unexpectedly"),
        ({"s": {"user_name": "x"}, "condition": "s | count() > 5"}, "aggregation pipes"),
        ({"s": {"user_name": "x"}, "condition": "1 of x*"}, "matches no selection"),
        ({"s": "keyword", "condition": "s"}, "must be a mapping"),
        ({"s": {"user_name": "x"}}, "condition must be"),
    ],
)
def test_invalid_detections_explain_the_problem(detection: dict[str, Any], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        compile_detection(detection, "test")


def test_logsource_scopes_detection() -> None:
    rule = build_rule(VALID_RULE | {"logsource": {"category": "authentication", "service": "ssh"}})
    assert isinstance(rule, SingleEventRule)
    assert matches(
        rule.expression, EVENT | {"event_category": "authentication", "source_type": "ssh"}
    )
    assert not matches(rule.expression, EVENT | {"event_category": "web", "source_type": "ssh"})


def test_correlation_rule_is_parsed() -> None:
    rule = build_rule(
        VALID_RULE
        | {
            "detection": None,
            "correlation": {
                "type": "value_count",
                "rules": ["base"],
                "group-by": ["source_ip"],
                "timespan": "10m",
                "condition": {"field": "user_name", "gte": 10},
            },
        }
    )
    assert isinstance(rule, CorrelationRule)
    assert rule.type is CorrelationType.VALUE_COUNT
    assert rule.timespan == timedelta(minutes=10)
    assert rule.slide == timedelta(minutes=2)
    assert rule.value_field == "user_name"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"id": "not-a-uuid"}, "id"),
        ({"level": "urgent"}, "level"),
        ({"status": "draft"}, "status"),
        ({"unexpected": True}, "unexpected"),
        ({"detection": None}, "detection or a correlation"),
        (
            {
                "detection": None,
                "correlation": {"type": "event_count", "rules": ["x"], "timespan": "5m"},
            },
            "need a condition",
        ),
        (
            {
                "detection": None,
                "correlation": {
                    "type": "event_count",
                    "rules": ["x"],
                    "timespan": "5 minutes",
                    "condition": {"gte": 3},
                },
            },
            "invalid timespan",
        ),
    ],
)
def test_invalid_rules_raise_descriptive_errors(override: dict[str, Any], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        build_rule(VALID_RULE | override)


def test_invalid_yaml_reports_file(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yml"
    broken.write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleError, match="invalid YAML") as caught:
        load_rules([broken])
    assert caught.value.path == broken


def test_unknown_reference_and_missing_tag_are_rejected(tmp_path: Path) -> None:
    correlation = tmp_path / "correlation.yml"
    correlation.write_text(
        """
title: Orphan Correlation
id: 1d8e5b0c-65f2-4a39-bc1d-0f64f3a3e0b2
name: orphan
status: test
description: References a rule that does not exist.
tags: [attack.t1110]
correlation:
  type: event_count
  rules: [missing_rule]
  group-by: [source_ip]
  timespan: 5m
  condition: {gte: 3}
level: low
""",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="unknown rule 'missing_rule'"):
        load_rules([correlation])
    untagged = tmp_path / "untagged.yml"
    untagged.write_text(
        yaml.safe_dump({key: value for key, value in VALID_RULE.items() if key != "tags"}),
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match=r"attack.tXXXX"):
        load_rules([untagged])


def test_sliding_windows_cover_each_event() -> None:
    moment = datetime(2026, 9, 28, 10, 7, 30, tzinfo=UTC)
    starts = window_starts(moment, timedelta(minutes=5), timedelta(minutes=1))
    assert len(starts) == 5
    assert all(start <= moment < start + timedelta(minutes=5) for start in starts)
    assert min(starts) == datetime(2026, 9, 28, 10, 3, tzinfo=UTC)


def test_shipped_rules_have_unique_ids_and_tags() -> None:
    rules = load_rules()
    assert len({rule.meta.id for rule in rules.rules}) == len(rules.rules)
    for rule in rules.alerting:
        assert rule.meta.techniques
        assert rule.meta.tactics
