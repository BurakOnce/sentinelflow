from collections.abc import Sequence
from ipaddress import IPv4Network

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F

from detections.engine.expressions import (
    AllOf,
    Expression,
    FieldMatch,
    Negation,
    Operator,
    Scalar,
)
from detections.engine.hits import CONTEXT_FIELDS, micros
from detections.engine.model import CorrelationRule, SingleEventRule
from detections.engine.python_backend import wildcard_regex

NUMERIC_COMPARISONS = {
    Operator.GT: Column.__gt__,
    Operator.GTE: Column.__ge__,
    Operator.LT: Column.__lt__,
    Operator.LTE: Column.__le__,
}


def _ipv4_number(column: Column) -> Column:
    octets = F.split(column, r"\.")
    return (
        octets.getItem(0).cast("long") * 16_777_216
        + octets.getItem(1).cast("long") * 65_536
        + octets.getItem(2).cast("long") * 256
        + octets.getItem(3).cast("long")
    )


def _single(column: Column, operator: Operator, expected: Scalar) -> Column:
    if expected is None:
        return column.isNull() if operator is Operator.EQUALS else F.lit(False)
    if operator in NUMERIC_COMPARISONS:
        return NUMERIC_COMPARISONS[operator](column.cast("long"), F.lit(int(expected)))
    if isinstance(expected, int):
        return column == F.lit(expected)
    if operator is Operator.REGEX:
        return column.rlike(expected)
    if operator is Operator.CIDR:
        network = IPv4Network(expected, strict=False)
        number = _ipv4_number(column)
        return number.between(int(network.network_address), int(network.broadcast_address))
    lowered, needle = F.lower(column), expected.lower()
    if operator is Operator.CONTAINS:
        return lowered.contains(needle)
    if operator is Operator.STARTSWITH:
        return lowered.startswith(needle)
    if operator is Operator.ENDSWITH:
        return lowered.endswith(needle)
    if operator is Operator.WILDCARD:
        return lowered.rlike(wildcard_regex(needle))
    return lowered == F.lit(needle)


def compile_expression(expression: Expression) -> Column:
    if isinstance(expression, FieldMatch):
        column = F.col(expression.field)
        parts = [
            F.coalesce(_single(column, expression.operator, value), F.lit(False))
            for value in expression.values
        ]
        combined = parts[0]
        for part in parts[1:]:
            combined = (combined & part) if expression.match_all else (combined | part)
        return combined
    if isinstance(expression, Negation):
        return ~compile_expression(expression.child)
    children = [compile_expression(child) for child in expression.children]
    if not children:
        return F.lit(isinstance(expression, AllOf))
    combined = children[0]
    for child in children[1:]:
        combined = (combined & child) if isinstance(expression, AllOf) else (combined | child)
    return combined


def single_event_matches(events: DataFrame, rules: Sequence[SingleEventRule]) -> DataFrame:
    candidates = [
        F.when(
            compile_expression(rule.expression) & F.col(rule.entity_field).isNotNull(),
            F.struct(
                F.lit(rule.meta.id).alias("rule_id"),
                F.col(rule.entity_field).cast("string").alias("entity"),
            ),
        )
        for rule in rules
    ]
    matched = F.filter(F.array(*candidates), lambda item: item.isNotNull())
    return (
        events.withColumn("matches", matched)
        .filter(F.size("matches") > 0)
        .select("*", F.explode("matches").alias("match"))
        .drop("matches")
        .select("*", "match.rule_id", "match.entity")
        .drop("match")
    )


def _string(field: str) -> Column:
    return F.col(field).cast("string")


def correlation_entries(events: DataFrame, rules: Sequence[CorrelationRule]) -> DataFrame:
    candidates = []
    for rule in rules:
        group = F.to_json(F.array(*[_string(name) for name in rule.group_by]))
        has_group = F.lit(not rule.group_by)
        for name in rule.group_by:
            has_group = has_group | F.col(name).isNotNull()
        attributes = F.create_map(
            *[
                item
                for name in dict.fromkeys((*rule.attribute_fields, *CONTEXT_FIELDS))
                for item in (F.lit(name), _string(name))
            ]
        )
        for index, reference in enumerate(rule.references):
            candidates.append(
                F.when(
                    compile_expression(reference.expression) & has_group,
                    F.struct(
                        F.lit(rule.meta.id).alias("rule_id"),
                        group.alias("group_key"),
                        F.lit(index).alias("reference"),
                        F.lit(micros(rule.timespan)).alias("span_us"),
                        F.lit(micros(rule.slide)).alias("slide_us"),
                        attributes.alias("attributes"),
                    ),
                )
            )
    matched = F.filter(F.array(*candidates), lambda item: item.isNotNull())
    exploded = (
        events.select("event_id", "timestamp", F.explode(matched).alias("entry"))
        .select("event_id", "timestamp", "entry.*")
        .withColumn("moment_us", F.unix_micros("timestamp"))
        .withColumn("latest_us", F.col("moment_us") - F.pmod("moment_us", "slide_us"))
    )
    starts = F.filter(
        F.transform(
            F.sequence(
                F.lit(0).cast("long"), (F.col("span_us") / F.col("slide_us")).cast("long") - 1
            ),
            lambda index: F.col("latest_us") - index * F.col("slide_us"),
        ),
        lambda start: start + F.col("span_us") > F.col("moment_us"),
    )
    return (
        exploded.select("*", F.explode(starts).alias("start_us"))
        .withColumn("window_start", F.timestamp_micros("start_us"))
        .withColumn("window_end", F.timestamp_micros(F.col("start_us") + F.col("span_us")))
        .drop("moment_us", "latest_us", "start_us", "span_us", "slide_us")
    )


def aggregate_windows(entries: DataFrame) -> DataFrame:
    return entries.groupBy("rule_id", "group_key", "window_start", "window_end").agg(
        F.collect_list(
            F.struct(
                F.unix_micros("timestamp").alias("timestamp_us"),
                "event_id",
                "reference",
                "attributes",
            )
        ).alias("entries")
    )
