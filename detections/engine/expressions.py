import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Any

from detections.engine.errors import RuleError
from streaming.schema import EVENT_FIELDS, FieldType

FIELD_TYPES = {field.name: field.type for field in EVENT_FIELDS}
NUMERIC_TYPES = frozenset({FieldType.UINT16})
Scalar = str | int | None


class Operator(StrEnum):
    EQUALS = "equals"
    WILDCARD = "wildcard"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "re"
    CIDR = "cidr"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"


STRING_OPERATORS = frozenset(
    {Operator.CONTAINS, Operator.STARTSWITH, Operator.ENDSWITH, Operator.REGEX, Operator.WILDCARD}
)
NUMERIC_OPERATORS = frozenset({Operator.GT, Operator.GTE, Operator.LT, Operator.LTE})
MODIFIERS = {operator.value: operator for operator in Operator if operator is not Operator.WILDCARD}


@dataclass(frozen=True, slots=True)
class FieldMatch:
    field: str
    operator: Operator
    values: tuple[Scalar, ...]
    match_all: bool = False


@dataclass(frozen=True, slots=True)
class AllOf:
    children: tuple["Expression", ...]


@dataclass(frozen=True, slots=True)
class AnyOf:
    children: tuple["Expression", ...]


@dataclass(frozen=True, slots=True)
class Negation:
    child: "Expression"


Expression = FieldMatch | AllOf | AnyOf | Negation


def has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def _field_match(key: str, raw_values: Any, rule: str) -> FieldMatch:
    field, *modifiers = key.split("|")
    if field not in FIELD_TYPES:
        raise RuleError(rule, f"unknown field {field!r}")
    unknown = [modifier for modifier in modifiers if modifier not in {*MODIFIERS, "all"}]
    if unknown:
        raise RuleError(rule, f"unsupported modifier {'|'.join(unknown)!r} on {field!r}")
    operators = [MODIFIERS[modifier] for modifier in modifiers if modifier != "all"]
    if len(operators) > 1:
        raise RuleError(rule, f"only one value modifier is supported on {field!r}")
    values = tuple(raw_values) if isinstance(raw_values, list) else (raw_values,)
    if not values:
        raise RuleError(rule, f"empty value list for {field!r}")
    for value in values:
        if (value is not None and not isinstance(value, str | int)) or isinstance(value, bool):
            raise RuleError(rule, f"unsupported value {value!r} for {field!r}")
    operator: Operator = operators[0] if operators else Operator.EQUALS
    numeric = FIELD_TYPES[field] in NUMERIC_TYPES
    if operator in NUMERIC_OPERATORS and not numeric:
        raise RuleError(rule, f"modifier {operator} needs a numeric field, {field!r} is not")
    if operator in STRING_OPERATORS and numeric:
        raise RuleError(rule, f"modifier {operator} needs a text field, {field!r} is numeric")
    if operator is Operator.CIDR and FIELD_TYPES[field] is not FieldType.IPV4:
        raise RuleError(rule, f"cidr modifier needs an address field, {field!r} is not")
    if operator is Operator.REGEX:
        for value in values:
            try:
                re.compile(str(value))
            except re.error as error:
                raise RuleError(
                    rule, f"invalid regular expression for {field!r}: {error}"
                ) from None
    values = tuple(_coerce(value, numeric, field, rule) for value in values)
    if operator is Operator.EQUALS and any(
        isinstance(value, str) and has_wildcard(value) for value in values
    ):
        operator = Operator.WILDCARD
    return FieldMatch(field, operator, values, "all" in modifiers)


def _coerce(value: Scalar, numeric: bool, field: str, rule: str) -> Scalar:
    if value is None:
        return None
    if not numeric:
        return str(value)
    try:
        return int(value)
    except ValueError:
        raise RuleError(rule, f"{field!r} is numeric, {value!r} is not a number") from None


def _selection(name: str, body: Any, rule: str) -> Expression:
    if isinstance(body, Mapping):
        if not body:
            raise RuleError(rule, f"selection {name!r} is empty")
        return AllOf(tuple(_field_match(str(key), value, rule) for key, value in body.items()))
    if isinstance(body, list) and body and all(isinstance(item, Mapping) for item in body):
        return AnyOf(tuple(_selection(name, item, rule) for item in body))
    raise RuleError(rule, f"selection {name!r} must be a mapping of fields or a list of mappings")


TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


class _ConditionParser:
    def __init__(self, text: str, selections: Mapping[str, Expression], rule: str) -> None:
        if "|" in text:
            raise RuleError(rule, "aggregation pipes in conditions are not supported")
        self._rule = rule
        self._selections = selections
        self._tokens = self._tokenize(text)
        self._position = 0

    def _tokenize(self, text: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(text.rstrip()):
            match = TOKEN.match(text, position)
            if match is None:
                raise RuleError(self._rule, f"cannot parse condition near {text[position:]!r}")
            tokens.append(match.group(1))
            position = match.end()
        return tokens

    def _peek(self) -> str | None:
        return self._tokens[self._position] if self._position < len(self._tokens) else None

    def _take(self) -> str:
        symbol = self._peek()
        if symbol is None:
            raise RuleError(self._rule, "condition ended unexpectedly")
        self._position += 1
        return symbol

    def parse(self) -> Expression:
        expression = self._or()
        if self._peek() is not None:
            raise RuleError(self._rule, f"unexpected token {self._peek()!r} in condition")
        return expression

    def _or(self) -> Expression:
        children = [self._and()]
        while self._peek() == "or":
            self._take()
            children.append(self._and())
        return children[0] if len(children) == 1 else AnyOf(tuple(children))

    def _and(self) -> Expression:
        children = [self._not()]
        while self._peek() == "and":
            self._take()
            children.append(self._not())
        return children[0] if len(children) == 1 else AllOf(tuple(children))

    def _not(self) -> Expression:
        if self._peek() == "not":
            self._take()
            return Negation(self._not())
        return self._primary()

    def _primary(self) -> Expression:
        symbol = self._take()
        if symbol == "(":
            expression = self._or()
            if self._take() != ")":
                raise RuleError(self._rule, "missing closing parenthesis in condition")
            return expression
        if symbol in {"1", "all"} and self._peek() == "of":
            self._take()
            return self._quantified(symbol, self._take())
        if symbol in {"and", "or", "of", ")"}:
            raise RuleError(self._rule, f"unexpected {symbol!r} in condition")
        if symbol not in self._selections:
            raise RuleError(self._rule, f"condition references unknown selection {symbol!r}")
        return self._selections[symbol]

    def _quantified(self, quantifier: str, pattern: str) -> Expression:
        names = sorted(
            name for name in self._selections if pattern == "them" or fnmatchcase(name, pattern)
        )
        if not names:
            raise RuleError(self._rule, f"{quantifier} of {pattern} matches no selection")
        children = tuple(self._selections[name] for name in names)
        return AnyOf(children) if quantifier == "1" else AllOf(children)


def compile_detection(detection: Mapping[str, Any], rule: str) -> Expression:
    condition = detection.get("condition")
    if isinstance(condition, list):
        if len(condition) != 1:
            raise RuleError(rule, "only a single condition is supported")
        condition = condition[0]
    if not isinstance(condition, str) or not condition.strip():
        raise RuleError(rule, "detection.condition must be a non-empty string")
    selections = {
        name: _selection(name, body, rule)
        for name, body in detection.items()
        if name not in {"condition", "timeframe"}
    }
    if not selections:
        raise RuleError(rule, "detection needs at least one selection")
    return _ConditionParser(condition, selections, rule).parse()
