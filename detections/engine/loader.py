import datetime as dt
import os
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from detections.engine.errors import RuleError
from detections.engine.expressions import (
    FIELD_TYPES,
    AllOf,
    Expression,
    FieldMatch,
    Operator,
    compile_detection,
)
from detections.engine.model import (
    ENTITY_TYPES,
    TECHNIQUE_TAG,
    CorrelationRule,
    CorrelationType,
    DetectorRule,
    HavingCondition,
    Level,
    Reference,
    Rule,
    RuleMetadata,
    SingleEventRule,
    Threshold,
    parse_duration,
)

RULES_DIR = Path(
    os.environ.get("SENTINELFLOW_RULES_DIR", Path(__file__).resolve().parent.parent / "rules")
)
LOGSOURCE_FIELDS = {"category": "event_category", "service": "source_type"}
DEFAULT_SLIDE_DIVISOR = 5


class ThresholdModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    eq: float | None = None
    field: str | None = None

    def threshold(self) -> Threshold:
        return Threshold(self.gt, self.gte, self.lt, self.lte, self.eq)


class HavingModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    aggregate: Literal["value_count", "ratio"]
    field: str
    equals: str | None = None
    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None


class ExtensionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: str | None = None
    suppression: str | None = None
    slide: str | None = None
    detector: str | None = None
    parameters: dict[str, bool | int | float | str] = Field(default_factory=dict)
    having: list[HavingModel] = Field(default_factory=list)


class CorrelationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    type: CorrelationType
    rules: list[str] = Field(min_length=1)
    group_by: list[str] = Field(default_factory=list, alias="group-by")
    timespan: str
    condition: ThresholdModel | None = None
    generate: bool = False


class RuleDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=3)
    id: str
    name: str | None = None
    status: Literal["stable", "test", "experimental", "deprecated", "unsupported"]
    description: str = Field(min_length=10)
    references: list[str] = Field(default_factory=list)
    author: str | None = None
    date: dt.date | str | None = None
    modified: dt.date | str | None = None
    tags: list[str] = Field(default_factory=list)
    logsource: dict[str, str] | None = None
    detection: dict[str, Any] | None = None
    correlation: CorrelationModel | None = None
    fields: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    level: Level
    sentinelflow: ExtensionModel = Field(default_factory=ExtensionModel)

    @field_validator("id")
    @classmethod
    def _uuid(cls, value: str) -> str:
        uuid.UUID(value)
        return value


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: tuple[Rule, ...]

    def by_name(self, name: str) -> Rule:
        return next(rule for rule in self.rules if rule.meta.name == name)

    def by_id(self, rule_id: str) -> Rule:
        return next(rule for rule in self.rules if rule.meta.id == rule_id)

    @property
    def alerting(self) -> tuple[Rule, ...]:
        referenced: set[str] = set()
        for rule in self.rules:
            if isinstance(rule, CorrelationRule) and not rule.generate:
                referenced.update(rule.rule_names)
        return tuple(rule for rule in self.rules if rule.meta.name not in referenced)

    @property
    def single_event(self) -> tuple[SingleEventRule, ...]:
        return tuple(rule for rule in self.alerting if isinstance(rule, SingleEventRule))

    @property
    def correlations(self) -> tuple[CorrelationRule, ...]:
        return tuple(rule for rule in self.alerting if isinstance(rule, CorrelationRule))

    @property
    def detectors(self) -> tuple[DetectorRule, ...]:
        return tuple(rule for rule in self.alerting if isinstance(rule, DetectorRule))


def _error_text(error: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in item['loc']) or 'document'}: {item['msg']}"
        for item in error.errors()
    )


def _metadata(document: RuleDocument, path: Path | None) -> RuleMetadata:
    return RuleMetadata(
        id=document.id,
        name=document.name or document.id,
        title=document.title,
        description=document.description.strip(),
        status=document.status,
        level=document.level,
        tags=tuple(document.tags),
        references=tuple(document.references),
        falsepositives=tuple(document.falsepositives),
        path=path,
    )


def _logsource_expression(logsource: Mapping[str, str] | None) -> list[Expression]:
    return [
        FieldMatch(LOGSOURCE_FIELDS[key], Operator.EQUALS, (value,))
        for key, value in (logsource or {}).items()
        if key in LOGSOURCE_FIELDS
    ]


def _detection_expression(document: RuleDocument, rule: str) -> Expression:
    if document.detection is None:
        raise RuleError(rule, "rule needs either a detection or a correlation section")
    body = compile_detection(document.detection, rule)
    scope = _logsource_expression(document.logsource)
    return AllOf((*scope, body)) if scope else body


def _required_duration(value: str, rule: str, label: str) -> timedelta:
    try:
        return parse_duration(value)
    except ValueError as error:
        raise RuleError(rule, f"{label}: {error}") from None


def _duration(value: str | None, rule: str, label: str) -> timedelta | None:
    return None if value is None else _required_duration(value, rule, label)


def _entity(value: str | None, default: str, rule: str) -> str:
    entity = value or default
    if entity not in ENTITY_TYPES:
        raise RuleError(rule, f"entity must be one of {', '.join(ENTITY_TYPES)}, got {entity!r}")
    return entity


def _check_field(name: str, rule: str, label: str) -> None:
    if name not in FIELD_TYPES:
        raise RuleError(rule, f"{label} references unknown field {name!r}")


def _correlation(
    document: RuleDocument, correlation: CorrelationModel, meta: RuleMetadata
) -> CorrelationRule:
    rule = meta.name
    if document.detection is not None:
        raise RuleError(rule, "a rule cannot have both detection and correlation sections")
    for name in correlation.group_by:
        _check_field(name, rule, "group-by")
    counting = correlation.type in {CorrelationType.EVENT_COUNT, CorrelationType.VALUE_COUNT}
    if counting and correlation.condition is None:
        raise RuleError(rule, f"{correlation.type} correlations need a condition")
    condition = correlation.condition or ThresholdModel(gte=1)
    value_field = condition.field
    if correlation.type is CorrelationType.VALUE_COUNT:
        if value_field is None:
            raise RuleError(rule, "value_count correlations need condition.field")
        _check_field(value_field, rule, "condition.field")
    elif value_field is not None:
        raise RuleError(rule, "condition.field is only valid for value_count correlations")
    threshold = condition.threshold()
    if threshold.gt is None and threshold.gte is None and threshold.eq is None:
        raise RuleError(rule, "condition needs a lower bound (gt, gte or eq)")
    timespan = _required_duration(correlation.timespan, rule, "timespan")
    slide = _duration(document.sentinelflow.slide, rule, "slide") or (
        timespan / DEFAULT_SLIDE_DIVISOR
    )
    if timespan % slide:
        raise RuleError(rule, "timespan must be a multiple of slide")
    having = []
    for item in document.sentinelflow.having:
        _check_field(item.field, rule, "having")
        if item.aggregate == "ratio" and item.equals is None:
            raise RuleError(rule, "ratio conditions need an equals value")
        having.append(
            HavingCondition(
                item.aggregate,
                item.field,
                Threshold(item.gt, item.gte, item.lt, item.lte),
                item.equals,
            )
        )
    return CorrelationRule(
        meta=meta,
        type=correlation.type,
        rule_names=tuple(correlation.rules),
        group_by=tuple(correlation.group_by),
        timespan=timespan,
        slide=slide,
        condition=threshold,
        value_field=value_field,
        having=tuple(having),
        generate=correlation.generate,
        suppression=_duration(document.sentinelflow.suppression, rule, "suppression"),
    )


def build_rule(raw: Mapping[str, Any], path: Path | None = None) -> Rule:
    label = str(raw.get("name") or raw.get("title") or raw.get("id") or "<unnamed>")
    try:
        document = RuleDocument.model_validate(raw)
    except ValidationError as error:
        raise RuleError(label, _error_text(error), path) from None
    meta = _metadata(document, path)
    try:
        if document.correlation is not None:
            return _correlation(document, document.correlation, meta)
        expression = _detection_expression(document, meta.name)
        extension = document.sentinelflow
        suppression = _duration(extension.suppression, meta.name, "suppression")
        if extension.detector is not None:
            return DetectorRule(
                meta=meta,
                expression=expression,
                detector=extension.detector,
                entity_field=_entity(extension.entity, "user_name", meta.name),
                parameters=dict(extension.parameters),
                suppression=suppression,
            )
        return SingleEventRule(
            meta=meta,
            expression=expression,
            entity_field=_entity(extension.entity, "source_ip", meta.name),
            suppression=suppression,
        )
    except RuleError as error:
        raise error.at(path) if path else error from None


def _resolve(rules: list[Rule]) -> list[Rule]:
    by_name: dict[str, Rule] = {}
    for rule in rules:
        if rule.meta.name in by_name:
            raise RuleError(rule.meta.name, "duplicate rule name", rule.meta.path)
        by_name[rule.meta.name] = rule

    def references(rule: CorrelationRule) -> tuple[Reference, ...]:
        resolved = []
        for name in rule.rule_names:
            target = by_name.get(name)
            if target is None:
                raise RuleError(rule.meta.name, f"references unknown rule {name!r}", rule.meta.path)
            if isinstance(target, SingleEventRule):
                resolved.append(Reference(name, target.expression))
                continue
            temporal = rule.type in {CorrelationType.TEMPORAL, CorrelationType.TEMPORAL_ORDERED}
            if not (
                isinstance(target, CorrelationRule)
                and target.type is CorrelationType.EVENT_COUNT
                and temporal
            ):
                raise RuleError(
                    rule.meta.name,
                    f"{rule.type} can only reference detection rules, {name!r} is not one",
                    rule.meta.path,
                )
            if target.group_by != rule.group_by:
                raise RuleError(
                    rule.meta.name, f"group-by must match referenced rule {name!r}", rule.meta.path
                )
            inner = references(target)
            if len(inner) != 1:
                raise RuleError(
                    rule.meta.name,
                    f"nested rule {name!r} must reference exactly one detection rule",
                    rule.meta.path,
                )
            resolved.append(Reference(name, inner[0].expression, target.condition.minimum_count))
        return tuple(resolved)

    return [
        replace(rule, references=references(rule)) if isinstance(rule, CorrelationRule) else rule
        for rule in rules
    ]


def _documents(path: Path) -> Iterable[Mapping[str, Any]]:
    try:
        documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as error:
        raise RuleError(path.stem, f"invalid YAML: {error}", path) from None
    for document in documents:
        if document is None:
            continue
        if not isinstance(document, Mapping):
            raise RuleError(path.stem, "each YAML document must be a mapping", path)
        yield document


def load_rules(paths: Iterable[Path] | None = None) -> RuleSet:
    files = sorted(paths) if paths is not None else sorted(RULES_DIR.glob("*.yml"))
    rules = [build_rule(document, path) for path in files for document in _documents(path)]
    ids = [rule.meta.id for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        raise RuleError(duplicates[0], "duplicate rule id")
    rule_set = RuleSet(tuple(_resolve(rules)))
    for rule in rule_set.alerting:
        if not any(TECHNIQUE_TAG.match(tag) for tag in rule.meta.tags):
            raise RuleError(
                rule.meta.name, "alerting rules need an attack.tXXXX tag", rule.meta.path
            )
    return rule_set
