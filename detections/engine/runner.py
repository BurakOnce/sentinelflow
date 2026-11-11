from collections.abc import Iterable, Mapping, Sequence
from datetime import timedelta
from typing import Any

from detections.engine.alerts import Alert, AlertManager
from detections.engine.detectors import DETECTORS, MemoryStateStore, StateStore
from detections.engine.hits import Hit
from detections.engine.loader import RuleSet
from detections.engine.python_backend import correlation_hits, matches, single_event_hits
from enrichment.geo import GeoLookup

DEFAULT_SUPPRESSION = timedelta(minutes=30)


def evaluate_hits(
    rules: RuleSet,
    events: Sequence[Mapping[str, Any]],
    geo: GeoLookup,
    state: StateStore | None = None,
) -> list[Hit]:
    store = state or MemoryStateStore()
    hits: list[Hit] = []
    for single in rules.single_event:
        hits += single_event_hits(single, events)
    for correlation in rules.correlations:
        hits += correlation_hits(correlation, events)
    for detector in rules.detectors:
        selected = [event for event in events if matches(detector.expression, event)]
        hits += DETECTORS[detector.detector](detector, selected, store, geo)
    return hits


def evaluate(
    rules: RuleSet,
    events: Iterable[Mapping[str, Any]],
    geo: GeoLookup,
    suppression: timedelta = DEFAULT_SUPPRESSION,
) -> list[Alert]:
    ordered = sorted(events, key=lambda event: (event["timestamp"], event["event_id"]))
    manager = AlertManager(rules, suppression)
    manager.apply(evaluate_hits(rules, ordered, geo))
    return sorted(manager.open_alerts(), key=lambda alert: (alert.first_seen, alert.rule_name))
