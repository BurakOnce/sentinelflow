from collections.abc import Callable, Mapping

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F

from streaming.parsing.formats import (
    FORMATS,
    IPV4,
    UINT16_FIELDS,
    UINT16_MAX,
    Derived,
    JsonFormat,
    LinePattern,
    Lookup,
    ParseErrorCode,
    RegexFormat,
)
from streaming.schema import EVENT_FIELDS, FieldType

PARSE_ERROR = "parse_error"
PARSED_FIELDS = tuple(
    field.name for field in EVENT_FIELDS if field.name not in {"event_id", "ingest_time"}
)
Getter = Callable[[str], Column]


def _null_if(column: Column, tokens: frozenset[str]) -> Column:
    empty = column == F.lit("")
    for token in sorted(tokens):
        empty = empty | (column == F.lit(token))
    return F.when(empty, F.lit(None).cast("string")).otherwise(column)


def _derive(rule: Derived, get: Getter) -> Column:
    value = get(rule.key)
    if isinstance(rule, Lookup):
        mapped: Column = F.lit(None).cast("string")
        for key, result in rule.mapping.items():
            mapped = F.when(value == F.lit(key), F.lit(result)).otherwise(mapped)
        return mapped
    status = value.try_cast("int")
    return F.when(status.isNull(), F.lit(None).cast("string")).otherwise(
        F.when(status < 400, F.lit("success")).otherwise(F.lit("failure"))
    )


def _field_values(
    constants: Mapping[str, str],
    captures: Mapping[str, str],
    derived: Mapping[str, Derived],
    get: Getter,
) -> dict[str, Column]:
    values = {name: F.lit(value) for name, value in constants.items()}
    values |= {name: get(key) for name, key in captures.items()}
    values |= {name: _derive(rule, get) for name, rule in derived.items()}
    return values


def _pattern_getter(pattern: LinePattern, raw: Column, tokens: frozenset[str]) -> Getter:
    def get(name: str) -> Column:
        extracted = F.regexp_extract(raw, pattern.spark_regex, pattern.group_index(name))
        return _null_if(extracted, tokens)

    return get


def _regex_columns(fmt: RegexFormat, raw: Column) -> tuple[dict[str, Column], Column]:
    index: Column = F.lit(None).cast("int")
    for position in reversed(range(len(fmt.patterns))):
        matched = raw.rlike(fmt.patterns[position].spark_regex)
        index = F.when(matched, F.lit(position)).otherwise(index)
    columns: dict[str, Column] = {}
    for position, pattern in enumerate(fmt.patterns):
        get = _pattern_getter(pattern, raw, fmt.null_tokens)
        values = _field_values(pattern.constants, pattern.captures, pattern.derived, get)
        values["timestamp"] = F.try_to_timestamp(
            get(fmt.timestamp_key), F.lit(fmt.timestamp_format.spark)
        )
        for name in PARSED_FIELDS:
            if name in values:
                previous = columns.get(name, F.lit(None))
                columns[name] = F.when(index == position, values[name]).otherwise(previous)
    error = (
        F.when(index.isNull(), F.lit(ParseErrorCode.UNRECOGNIZED_FORMAT.value))
        .when(columns["timestamp"].isNull(), F.lit(ParseErrorCode.INVALID_TIMESTAMP.value))
        .otherwise(F.lit(None))
    )
    return columns, error


def _json_columns(fmt: JsonFormat, raw: Column) -> tuple[dict[str, Column], Column]:
    def get(key: str) -> Column:
        return F.get_json_object(raw, f"$.{key}")

    document = F.get_json_object(raw, "$")
    invalid_json = document.isNull() | ~F.ltrim(raw).startswith("{")
    missing = F.lit(False)
    for key in fmt.required:
        missing = missing | get(key).isNull()
    invalid_ip = F.lit(False)
    for key in fmt.ip_keys:
        invalid_ip = invalid_ip | ~get(key).rlike(f"^{IPV4}$")
    columns = _field_values(fmt.constants, fmt.captures, fmt.derived, get)
    columns["timestamp"] = F.try_to_timestamp(
        get(fmt.timestamp_key), F.lit(fmt.timestamp_format.spark)
    )
    error = (
        F.when(invalid_json, F.lit(ParseErrorCode.INVALID_JSON.value))
        .when(missing, F.lit(ParseErrorCode.MISSING_FIELD.value))
        .when(invalid_ip, F.lit(ParseErrorCode.INVALID_FIELD.value))
        .when(columns["timestamp"].isNull(), F.lit(ParseErrorCode.INVALID_TIMESTAMP.value))
        .otherwise(F.lit(None))
    )
    return columns, error


def _typed(name: str, column: Column) -> Column:
    field_type = next(field.type for field in EVENT_FIELDS if field.name == name)
    if field_type is FieldType.UINT16:
        return column.try_cast("int")
    if field_type is FieldType.TIMESTAMP:
        return column
    return column.cast("string")


def normalize(frame: DataFrame) -> DataFrame:
    source = F.col("source_type")
    raw = F.col("raw_message")
    fields: dict[str, Column] = {name: F.lit(None) for name in PARSED_FIELDS}
    fields["source_type"] = source
    fields["raw_message"] = raw
    error: Column = F.lit(ParseErrorCode.UNKNOWN_SOURCE.value)
    for source_type, fmt in FORMATS.items():
        is_source = source == F.lit(source_type)
        if isinstance(fmt, JsonFormat):
            columns, source_error = _json_columns(fmt, raw)
        else:
            columns, source_error = _regex_columns(fmt, raw)
        for name, column in columns.items():
            fields[name] = F.when(is_source, column).otherwise(fields[name])
        error = F.when(is_source, source_error).otherwise(error)
    typed = {name: _typed(name, column) for name, column in fields.items()}
    out_of_range = F.lit(False)
    for name in sorted(UINT16_FIELDS):
        out_of_range = out_of_range | F.coalesce(typed[name] > UINT16_MAX, F.lit(False))
    error = F.when(
        error.isNull() & out_of_range, F.lit(ParseErrorCode.NUMBER_OUT_OF_RANGE.value)
    ).otherwise(error)
    passthrough = [column for column in frame.columns if column not in typed]
    return frame.select(
        *passthrough,
        F.sha2(raw, 256).alias("event_id"),
        *(typed[name].alias(name) for name in PARSED_FIELDS if name != "source_type"),
        source.alias("source_type"),
        error.alias(PARSE_ERROR),
    )
