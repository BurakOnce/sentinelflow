import re
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from pathlib import Path

from detections.engine.expressions import Expression

DURATION = re.compile(r"^(\d+)([smhd])$")
DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_TAG = re.compile(r"^attack\.([a-z]+(?:[-_][a-z]+)*)$")
ENTITY_TYPES = {
    "source_ip": "ip",
    "destination_ip": "ip",
    "user_name": "user",
    "host_name": "host",
}


class Level(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CorrelationType(StrEnum):
    EVENT_COUNT = "event_count"
    VALUE_COUNT = "value_count"
    TEMPORAL = "temporal"
    TEMPORAL_ORDERED = "temporal_ordered"


def parse_duration(value: str) -> timedelta:
    match = DURATION.match(value.strip())
    if match is None:
        raise ValueError(f"invalid timespan {value!r}, expected forms like 30s, 5m, 1h")
    return timedelta(**{DURATION_UNITS[match.group(2)]: int(match.group(1))})


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    id: str
    name: str
    title: str
    description: str
    status: str
    level: Level
    tags: tuple[str, ...]
    references: tuple[str, ...]
    falsepositives: tuple[str, ...]
    path: Path | None = None

    @property
    def techniques(self) -> tuple[str, ...]:
        return tuple(
            match.group(1).upper()
            for tag in self.tags
            if (match := TECHNIQUE_TAG.match(tag)) is not None
        )

    @property
    def tactics(self) -> tuple[str, ...]:
        return tuple(
            match.group(1).replace("_", "-")
            for tag in self.tags
            if TECHNIQUE_TAG.match(tag) is None and (match := TACTIC_TAG.match(tag)) is not None
        )


@dataclass(frozen=True, slots=True)
class Threshold:
    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    eq: float | None = None

    def satisfied(self, value: float) -> bool:
        checks = (
            self.gt is None or value > self.gt,
            self.gte is None or value >= self.gte,
            self.lt is None or value < self.lt,
            self.lte is None or value <= self.lte,
            self.eq is None or value == self.eq,
        )
        return all(checks)

    @property
    def minimum_count(self) -> int:
        if self.eq is not None:
            return int(self.eq)
        if self.gte is not None:
            return int(self.gte)
        if self.gt is not None:
            return int(self.gt) + 1
        return 1


@dataclass(frozen=True, slots=True)
class HavingCondition:
    aggregate: str
    field: str
    threshold: Threshold
    equals: str | None = None


@dataclass(frozen=True, slots=True)
class SingleEventRule:
    meta: RuleMetadata
    expression: Expression
    entity_field: str = "source_ip"
    suppression: timedelta | None = None


@dataclass(frozen=True, slots=True)
class Reference:
    name: str
    expression: Expression
    minimum_count: int = 1


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    meta: RuleMetadata
    type: CorrelationType
    rule_names: tuple[str, ...]
    group_by: tuple[str, ...]
    timespan: timedelta
    slide: timedelta
    condition: Threshold
    value_field: str | None = None
    having: tuple[HavingCondition, ...] = ()
    generate: bool = False
    suppression: timedelta | None = None
    references: tuple[Reference, ...] = field(default=())

    @property
    def entity_field(self) -> str | None:
        return self.group_by[0] if self.group_by else None

    @property
    def attribute_fields(self) -> tuple[str, ...]:
        names = [self.value_field] if self.value_field else []
        names += [condition.field for condition in self.having]
        return tuple(dict.fromkeys(name for name in names if name))


@dataclass(frozen=True, slots=True)
class DetectorRule:
    meta: RuleMetadata
    expression: Expression
    detector: str
    entity_field: str
    parameters: dict[str, bool | int | float | str]
    suppression: timedelta | None = None


Rule = SingleEventRule | CorrelationRule | DetectorRule


def entity_type(field_name: str | None) -> str:
    return ENTITY_TYPES.get(field_name or "", "global")
