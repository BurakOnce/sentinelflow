import hashlib
import json
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime

from streaming.parsing.formats import (
    APP,
    FIREWALL,
    FORMATS,
    IPV4,
    NGINX,
    SSH,
    UINT16_FIELDS,
    UINT16_MAX,
    Derived,
    JsonFormat,
    Lookup,
    ParseErrorCode,
    RegexFormat,
    TimestampFormat,
)
from streaming.schema import NormalizedEvent

IPV4_PATTERN = re.compile(rf"^{IPV4}$")


class ParseError(ValueError):
    def __init__(self, code: ParseErrorCode, source_type: str) -> None:
        super().__init__(f"{source_type}: {code}")
        self.code = code
        self.source_type = source_type


def event_id(raw_message: str) -> str:
    return hashlib.sha256(raw_message.encode("utf-8")).hexdigest()


def _timestamp(value: str | None, fmt: TimestampFormat) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.strptime(value, fmt.python).astimezone(UTC)
    except ValueError:
        return None


def _derive(rule: Derived, values: Mapping[str, str | None]) -> str | None:
    value = values.get(rule.key)
    if value is None:
        return None
    if isinstance(rule, Lookup):
        return rule.mapping.get(value)
    return "success" if int(value) < 400 else "failure"


def _build(
    source_type: str,
    raw_message: str,
    ingest_time: datetime,
    timestamp: datetime,
    fields: dict[str, str | None],
) -> NormalizedEvent:
    numbers = {name: int(fields[name] or 0) for name in UINT16_FIELDS if fields.get(name)}
    if any(number > UINT16_MAX for number in numbers.values()):
        raise ParseError(ParseErrorCode.NUMBER_OUT_OF_RANGE, source_type)
    return NormalizedEvent(
        event_id=event_id(raw_message),
        timestamp=timestamp,
        ingest_time=ingest_time,
        source_type=source_type,
        event_category=fields["event_category"] or "",
        event_action=fields["event_action"] or "",
        event_outcome=fields.get("event_outcome"),
        source_ip=fields.get("source_ip"),
        source_port=numbers.get("source_port"),
        destination_ip=fields.get("destination_ip"),
        destination_port=numbers.get("destination_port"),
        host_name=fields.get("host_name"),
        user_name=fields.get("user_name"),
        user_agent=fields.get("user_agent"),
        http_method=fields.get("http_method"),
        url_path=fields.get("url_path"),
        http_status=numbers.get("http_status"),
        raw_message=raw_message,
    )


def _parse_regex(fmt: RegexFormat, raw_message: str, ingest_time: datetime) -> NormalizedEvent:
    for pattern in fmt.patterns:
        match = pattern.compiled.match(raw_message)
        if match is None:
            continue
        groups = {
            name: None if value in fmt.null_tokens or value == "" else value
            for name, value in match.groupdict().items()
        }
        timestamp = _timestamp(groups.get(fmt.timestamp_key), fmt.timestamp_format)
        if timestamp is None:
            raise ParseError(ParseErrorCode.INVALID_TIMESTAMP, fmt.source_type)
        fields: dict[str, str | None] = dict(pattern.constants)
        fields |= {name: groups.get(group) for name, group in pattern.captures.items()}
        fields |= {name: _derive(rule, groups) for name, rule in pattern.derived.items()}
        return _build(fmt.source_type, raw_message, ingest_time, timestamp, fields)
    raise ParseError(ParseErrorCode.UNRECOGNIZED_FORMAT, fmt.source_type)


def _json_text(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value)


def _parse_json(fmt: JsonFormat, raw_message: str, ingest_time: datetime) -> NormalizedEvent:
    try:
        document = json.loads(raw_message)
    except ValueError:
        document = None
    if not isinstance(document, dict):
        raise ParseError(ParseErrorCode.INVALID_JSON, fmt.source_type)
    values = {key: _json_text(value) for key, value in document.items()}
    if any(values.get(key) is None for key in fmt.required):
        raise ParseError(ParseErrorCode.MISSING_FIELD, fmt.source_type)
    if any(not IPV4_PATTERN.match(values[key] or "") for key in fmt.ip_keys):
        raise ParseError(ParseErrorCode.INVALID_FIELD, fmt.source_type)
    timestamp = _timestamp(values.get(fmt.timestamp_key), fmt.timestamp_format)
    if timestamp is None:
        raise ParseError(ParseErrorCode.INVALID_TIMESTAMP, fmt.source_type)
    fields: dict[str, str | None] = dict(fmt.constants)
    fields |= {name: values.get(key) for name, key in fmt.captures.items()}
    fields |= {name: _derive(rule, values) for name, rule in fmt.derived.items()}
    return _build(fmt.source_type, raw_message, ingest_time, timestamp, fields)


def parse_line(source_type: str, raw_message: str, ingest_time: datetime) -> NormalizedEvent:
    fmt = FORMATS.get(source_type)
    if fmt is None:
        raise ParseError(ParseErrorCode.UNKNOWN_SOURCE, source_type)
    if isinstance(fmt, JsonFormat):
        return _parse_json(fmt, raw_message, ingest_time)
    return _parse_regex(fmt, raw_message, ingest_time)


def _parser_for(source_type: str) -> Callable[[str, datetime], NormalizedEvent]:
    def parse(raw_message: str, ingest_time: datetime) -> NormalizedEvent:
        return parse_line(source_type, raw_message, ingest_time)

    return parse


parse_nginx = _parser_for(NGINX.source_type)
parse_ssh = _parser_for(SSH.source_type)
parse_firewall = _parser_for(FIREWALL.source_type)
parse_app = _parser_for(APP.source_type)
