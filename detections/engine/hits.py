from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from detections.engine.model import (
    CorrelationRule,
    CorrelationType,
    HavingCondition,
    entity_type,
)

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
CONTEXT_FIELDS = ("event_category", "event_outcome", "source_ip", "user_name")


@dataclass(frozen=True, slots=True)
class Hit:
    rule_id: str
    entity_type: str
    entity: str
    first_seen: datetime
    last_seen: datetime
    detected_at: datetime
    event_ids: frozenset[str]
    source_ip: str | None = None
    user_name: str | None = None
    has_success: bool = False


@dataclass(frozen=True, slots=True)
class WindowEntry:
    timestamp: datetime
    event_id: str
    reference: int
    attributes: Mapping[str, str | None]

    @property
    def is_successful_login(self) -> bool:
        return (
            self.attributes.get("event_category") == "authentication"
            and self.attributes.get("event_outcome") == "success"
        )


def micros(value: datetime | timedelta) -> int:
    delta = value if isinstance(value, timedelta) else value - EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def window_starts(timestamp: datetime, timespan: timedelta, slide: timedelta) -> list[datetime]:
    moment, span, step = micros(timestamp), micros(timespan), micros(slide)
    latest = moment - moment % step
    return [
        EPOCH + timedelta(microseconds=latest - index * step)
        for index in range(span // step)
        if latest - index * step + span > moment
    ]


class _Progress:
    def __init__(self, rule: CorrelationRule) -> None:
        self.rule = rule
        self.events: set[str] = set()
        self.values: dict[str, set[str]] = {name: set() for name in rule.attribute_fields}
        self.ratio_hits: dict[int, int] = {}
        self.ratio_totals: dict[int, int] = {}
        self.stage = 0
        self.stage_count = 0
        self.reference_counts = [0] * len(rule.references)

    def add(self, entry: WindowEntry) -> None:
        self.events.add(entry.event_id)
        for name, seen in self.values.items():
            value = entry.attributes.get(name)
            if value is not None:
                seen.add(value)
        for index, condition in enumerate(self.rule.having):
            if condition.aggregate == "ratio":
                self.ratio_totals[index] = self.ratio_totals.get(index, 0) + 1
                matched = entry.attributes.get(condition.field) == condition.equals
                self.ratio_hits[index] = self.ratio_hits.get(index, 0) + int(matched)
        self.reference_counts[entry.reference] += 1
        if self.rule.type is CorrelationType.TEMPORAL_ORDERED and entry.reference == self.stage:
            self.stage_count += 1
            if self.stage_count >= self.rule.references[self.stage].minimum_count:
                self.stage += 1
                self.stage_count = 0

    def _having(self, index: int, condition: HavingCondition) -> bool:
        if condition.aggregate == "value_count":
            return condition.threshold.satisfied(len(self.values[condition.field]))
        total = self.ratio_totals.get(index, 0)
        return total > 0 and condition.threshold.satisfied(self.ratio_hits[index] / total)

    def satisfied(self) -> bool:
        rule = self.rule
        if rule.type is CorrelationType.TEMPORAL_ORDERED:
            primary = self.stage >= len(rule.references)
        elif rule.type is CorrelationType.TEMPORAL:
            primary = all(
                count >= reference.minimum_count
                for count, reference in zip(self.reference_counts, rule.references, strict=True)
            )
        elif rule.type is CorrelationType.VALUE_COUNT:
            primary = rule.condition.satisfied(len(self.values.get(rule.value_field or "", ())))
        else:
            primary = rule.condition.satisfied(len(self.events))
        return primary and all(
            self._having(index, condition) for index, condition in enumerate(rule.having)
        )


def evaluate_window(
    rule: CorrelationRule, group_values: Sequence[str | None], entries: Sequence[WindowEntry]
) -> Hit | None:
    ordered = sorted(
        {(entry.event_id, entry.reference): entry for entry in entries}.values(),
        key=lambda entry: (entry.timestamp, entry.event_id, entry.reference),
    )
    if not ordered:
        return None
    progress = _Progress(rule)
    detected: WindowEntry | None = None
    for entry in ordered:
        progress.add(entry)
        if detected is None and progress.satisfied():
            detected = entry
    if detected is None or not progress.satisfied():
        return None
    entity = next((value for value in group_values if value is not None), None)
    return Hit(
        rule_id=rule.meta.id,
        entity_type=entity_type(rule.entity_field),
        entity=entity or "all",
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
        detected_at=detected.timestamp,
        event_ids=frozenset(entry.event_id for entry in ordered),
        source_ip=detected.attributes.get("source_ip"),
        user_name=detected.attributes.get("user_name"),
        has_success=any(entry.is_successful_login for entry in ordered),
    )
