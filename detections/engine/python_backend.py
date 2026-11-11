import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import datetime
from functools import cache
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from detections.engine.expressions import (
    AllOf,
    Expression,
    FieldMatch,
    Negation,
    Operator,
    Scalar,
)
from detections.engine.hits import CONTEXT_FIELDS, Hit, WindowEntry, evaluate_window, window_starts
from detections.engine.model import CorrelationRule, SingleEventRule, entity_type

Event = Mapping[str, Any]


def wildcard_regex(value: str) -> str:
    parts = (".*" if char == "*" else "." if char == "?" else re.escape(char) for char in value)
    return "^" + "".join(parts) + "$"


@cache
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _single(operator: Operator, actual: Any, expected: Scalar) -> bool:
    if expected is None:
        return actual is None and operator is Operator.EQUALS
    if actual is None:
        return False
    if operator in {Operator.GT, Operator.GTE, Operator.LT, Operator.LTE}:
        number, bound = int(actual), int(expected)
        return {
            Operator.GT: number > bound,
            Operator.GTE: number >= bound,
            Operator.LT: number < bound,
            Operator.LTE: number <= bound,
        }[operator]
    if isinstance(expected, int):
        return bool(actual == expected)
    text, needle = str(actual), expected
    if operator is Operator.REGEX:
        return _compiled(needle).search(text) is not None
    if operator is Operator.CIDR:
        return IPv4Address(text) in IPv4Network(needle, strict=False)
    text, needle = text.lower(), needle.lower()
    if operator is Operator.CONTAINS:
        return needle in text
    if operator is Operator.STARTSWITH:
        return text.startswith(needle)
    if operator is Operator.ENDSWITH:
        return text.endswith(needle)
    if operator is Operator.WILDCARD:
        return _compiled(wildcard_regex(needle)).match(text) is not None
    return text == needle


def matches(expression: Expression, event: Event) -> bool:
    if isinstance(expression, FieldMatch):
        actual = event.get(expression.field)
        results = (_single(expression.operator, actual, value) for value in expression.values)
        return all(results) if expression.match_all else any(results)
    if isinstance(expression, Negation):
        return not matches(expression.child, event)
    if isinstance(expression, AllOf):
        return all(matches(child, event) for child in expression.children)
    return any(matches(child, event) for child in expression.children)


def _timestamp(event: Event) -> datetime:
    value = event["timestamp"]
    if not isinstance(value, datetime):
        raise TypeError(f"event timestamp must be a datetime, got {type(value).__name__}")
    return value


def single_event_hits(rule: SingleEventRule, events: Iterable[Event]) -> list[Hit]:
    hits = []
    for event in events:
        entity = event.get(rule.entity_field)
        if entity is None or not matches(rule.expression, event):
            continue
        moment = _timestamp(event)
        hits.append(
            Hit(
                rule_id=rule.meta.id,
                entity_type=entity_type(rule.entity_field),
                entity=str(entity),
                first_seen=moment,
                last_seen=moment,
                detected_at=moment,
                event_ids=frozenset({str(event["event_id"])}),
                source_ip=event.get("source_ip"),
                user_name=event.get("user_name"),
                has_success=event.get("event_category") == "authentication"
                and event.get("event_outcome") == "success",
            )
        )
    return hits


def window_entries(
    rule: CorrelationRule, event: Event
) -> list[tuple[tuple[str | None, ...], WindowEntry]]:
    group = tuple(
        None if event.get(name) is None else str(event.get(name)) for name in rule.group_by
    )
    if rule.group_by and all(value is None for value in group):
        return []
    fields = (*rule.attribute_fields, *CONTEXT_FIELDS)
    attributes = {
        name: None if event.get(name) is None else str(event.get(name)) for name in fields
    }
    return [
        (
            group,
            WindowEntry(_timestamp(event), str(event["event_id"]), index, attributes),
        )
        for index, reference in enumerate(rule.references)
        if matches(reference.expression, event)
    ]


def correlation_hits(rule: CorrelationRule, events: Iterable[Event]) -> list[Hit]:
    buckets: defaultdict[tuple[datetime, tuple[str | None, ...]], list[WindowEntry]] = defaultdict(
        list
    )
    for event in events:
        for group, entry in window_entries(rule, event):
            for start in window_starts(entry.timestamp, rule.timespan, rule.slide):
                buckets[(start, group)].append(entry)
    hits = []
    for (_, group), entries in sorted(buckets.items(), key=lambda item: item[0][0]):
        hit = evaluate_window(rule, group, entries)
        if hit is not None:
            hits.append(hit)
    return hits
