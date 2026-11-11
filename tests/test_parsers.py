from datetime import UTC, datetime

import pytest

from simulator.events import (
    AppAuthEvent,
    AuthResult,
    FailureReason,
    FirewallAction,
    FirewallEvent,
    HttpRequest,
    MfaMethod,
    SshEvent,
    SshEventKind,
)
from streaming.parsing.formats import ParseErrorCode
from streaming.parsing.python_parser import (
    ParseError,
    event_id,
    parse_app,
    parse_firewall,
    parse_line,
    parse_nginx,
    parse_ssh,
)
from streaming.schema import EVENT_FIELD_NAMES, NormalizedEvent

EVENT_TIME = datetime(2026, 9, 28, 10, 15, 30, 123456, tzinfo=UTC)
INGEST_TIME = datetime(2026, 9, 28, 10, 15, 31, tzinfo=UTC)


def ssh_line(kind: SshEventKind, username: str = "ayse.yilmaz") -> str:
    return SshEvent(
        EVENT_TIME, "85.100.1.2", "bastion-01", 4242, kind, username, 51514, 1001, "Key"
    ).render()


def nginx_line(path: str = "/dashboard", status: int = 200, agent: str = "curl/8.5.0") -> str:
    return HttpRequest(EVENT_TIME, "78.160.4.5", "GET", path, status, 512, agent).render()


def firewall_line(action: FirewallAction = FirewallAction.DROP, protocol: str = "TCP") -> str:
    return FirewallEvent(
        timestamp=EVENT_TIME,
        src_ip="36.100.2.3",
        host="fw-edge-01",
        action=action,
        dst_ip="203.0.113.10",
        protocol=protocol,
        src_port=40000,
        dst_port=3389,
        ttl=50,
        length=60,
        packet_id=777,
    ).render()


def app_line(result: AuthResult = AuthResult.FAILURE) -> str:
    return AppAuthEvent(
        timestamp=EVENT_TIME,
        src_ip="88.230.1.1",
        username="mehmet.kaya",
        result=result,
        reason=FailureReason.INVALID_PASSWORD if result is AuthResult.FAILURE else None,
        mfa=MfaMethod.PUSH,
        user_agent="Mozilla/5.0",
        request_id="abc123",
    ).render()


def assert_error(code: ParseErrorCode, source_type: str, raw: str) -> None:
    with pytest.raises(ParseError) as caught:
        parse_line(source_type, raw, INGEST_TIME)
    assert caught.value.code is code


def test_normalized_event_matches_schema_definition() -> None:
    assert tuple(NormalizedEvent.__dataclass_fields__) == EVENT_FIELD_NAMES


def test_event_id_is_sha256_of_raw_line() -> None:
    line = nginx_line()
    assert parse_nginx(line, INGEST_TIME).event_id == event_id(line)
    assert len(event_id(line)) == 64


def test_nginx_request_is_web_event_with_status_outcome() -> None:
    event = parse_nginx(nginx_line(status=404), INGEST_TIME)
    assert event.event_category == "web"
    assert event.event_action == "http_request"
    assert event.event_outcome == "failure"
    assert event.source_ip == "78.160.4.5"
    assert event.http_method == "GET"
    assert event.url_path == "/dashboard"
    assert event.http_status == 404
    assert event.user_name is None
    assert event.timestamp == EVENT_TIME.replace(microsecond=0)
    assert event.ingest_time == INGEST_TIME


def test_nginx_keeps_encoded_query_and_escaped_quotes() -> None:
    event = parse_nginx(nginx_line(path='/search?q="><svg/onload=alert(1)>'), INGEST_TIME)
    assert event.url_path == "/search?q=\\x22><svg/onload=alert(1)>"
    encoded = parse_nginx(nginx_line(path="/r?id=1%27%20OR%201=1"), INGEST_TIME)
    assert encoded.url_path == "/r?id=1%27%20OR%201=1"


def test_nginx_malformed_request_line_is_still_an_event() -> None:
    raw = '1.2.3.4 - - [28/Sep/2026:10:15:30 +0000] "-" 400 0 "-" "-"'
    event = parse_nginx(raw, INGEST_TIME)
    assert event.http_status == 400
    assert event.http_method is None
    assert event.user_agent is None


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("", ParseErrorCode.UNRECOGNIZED_FORMAT),
        ("not an access log", ParseErrorCode.UNRECOGNIZED_FORMAT),
        (nginx_line().replace("78.160.4.5", "999.1.1.1"), ParseErrorCode.UNRECOGNIZED_FORMAT),
        (nginx_line().replace("28/Sep/2026", "31/Feb/2026"), ParseErrorCode.INVALID_TIMESTAMP),
        (nginx_line().replace("28/Sep/2026", "28/Foo/2026"), ParseErrorCode.INVALID_TIMESTAMP),
        (nginx_line()[:-10], ParseErrorCode.UNRECOGNIZED_FORMAT),
    ],
)
def test_nginx_rejects_broken_lines(raw: str, code: ParseErrorCode) -> None:
    assert_error(code, "nginx", raw)


@pytest.mark.parametrize(
    ("kind", "action", "outcome"),
    [
        (SshEventKind.ACCEPTED_PASSWORD, "ssh_login", "success"),
        (SshEventKind.ACCEPTED_PUBLICKEY, "ssh_login", "success"),
        (SshEventKind.FAILED_PASSWORD, "ssh_login", "failure"),
        (SshEventKind.FAILED_PASSWORD_INVALID_USER, "ssh_login", "failure"),
        (SshEventKind.INVALID_USER, "ssh_invalid_user", "failure"),
        (SshEventKind.SESSION_OPENED, "ssh_session_open", "success"),
    ],
)
def test_ssh_messages_map_to_actions(kind: SshEventKind, action: str, outcome: str) -> None:
    event = parse_ssh(ssh_line(kind), INGEST_TIME)
    assert (event.event_action, event.event_outcome) == (action, outcome)
    assert event.user_name == "ayse.yilmaz"
    assert event.host_name == "bastion-01"
    assert event.timestamp == EVENT_TIME
    if kind is not SshEventKind.SESSION_OPENED:
        assert (event.source_ip, event.source_port) == ("85.100.1.2", 51514)


def test_ssh_invalid_user_with_empty_name() -> None:
    raw = ssh_line(SshEventKind.INVALID_USER).replace("Invalid user ayse.yilmaz", "Invalid user ")
    event = parse_ssh(raw, INGEST_TIME)
    assert event.user_name is None
    assert event.event_action == "ssh_invalid_user"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (
            ssh_line(SshEventKind.FAILED_PASSWORD).replace("Failed password", "Connection closed"),
            ParseErrorCode.UNRECOGNIZED_FORMAT,
        ),
        (
            ssh_line(SshEventKind.FAILED_PASSWORD).replace("2026-09-28T", "2026-13-28T"),
            ParseErrorCode.INVALID_TIMESTAMP,
        ),
        (
            ssh_line(SshEventKind.FAILED_PASSWORD).replace("port 51514", "port 99999"),
            ParseErrorCode.NUMBER_OUT_OF_RANGE,
        ),
    ],
)
def test_ssh_rejects_broken_lines(raw: str, code: ParseErrorCode) -> None:
    assert_error(code, "ssh", raw)


def test_firewall_drop_is_failed_network_event() -> None:
    event = parse_firewall(firewall_line(), INGEST_TIME)
    assert event.event_category == "network"
    assert (event.event_action, event.event_outcome) == ("firewall_drop", "failure")
    assert (event.source_ip, event.source_port) == ("36.100.2.3", 40000)
    assert (event.destination_ip, event.destination_port) == ("203.0.113.10", 3389)


def test_firewall_udp_and_accept() -> None:
    event = parse_firewall(firewall_line(FirewallAction.ACCEPT, "UDP"), INGEST_TIME)
    assert (event.event_action, event.event_outcome) == ("firewall_accept", "success")
    assert event.destination_port == 3389


def test_firewall_icmp_without_ports() -> None:
    raw = (
        "2026-09-28T10:15:30.123456+00:00 fw-edge-01 kernel: FW ACTION=DROP IN=eth0 OUT= "
        "SRC=36.100.2.3 DST=203.0.113.10 LEN=84 TOS=0x00 PREC=0x00 TTL=50 ID=1 PROTO=ICMP "
        "TYPE=8 CODE=0"
    )
    event = parse_firewall(raw, INGEST_TIME)
    assert event.source_port is None
    assert event.destination_port is None


def test_firewall_rejects_unknown_action() -> None:
    assert_error(
        ParseErrorCode.UNRECOGNIZED_FORMAT,
        "firewall",
        firewall_line().replace("ACTION=DROP", "ACTION=LOG"),
    )


def test_app_login_maps_json_fields() -> None:
    event = parse_app(app_line(AuthResult.SUCCESS), INGEST_TIME)
    assert event.event_category == "authentication"
    assert (event.event_action, event.event_outcome) == ("app_login", "success")
    assert event.user_name == "mehmet.kaya"
    assert event.source_ip == "88.230.1.1"
    assert event.user_agent == "Mozilla/5.0"
    assert event.host_name == "portal-auth"
    assert event.timestamp == EVENT_TIME.replace(microsecond=123000)


def test_app_unknown_result_has_no_outcome() -> None:
    raw = app_line().replace('"result":"failure"', '"result":"locked"')
    assert parse_app(raw, INGEST_TIME).event_outcome is None


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("{not json", ParseErrorCode.INVALID_JSON),
        ("[1, 2]", ParseErrorCode.INVALID_JSON),
        (
            '{"timestamp": "2026-09-28T10:15:30.123Z", "ip": "1.2.3.4"}',
            ParseErrorCode.MISSING_FIELD,
        ),
        (app_line().replace('"ip":"88.230.1.1"', '"ip":null'), ParseErrorCode.MISSING_FIELD),
        (app_line().replace("88.230.1.1", "88.230.1"), ParseErrorCode.INVALID_FIELD),
        (app_line().replace("2026-09-28T", "yesterday "), ParseErrorCode.INVALID_TIMESTAMP),
    ],
)
def test_app_rejects_broken_documents(raw: str, code: ParseErrorCode) -> None:
    assert_error(code, "app", raw)


def test_unknown_source_is_rejected() -> None:
    assert_error(ParseErrorCode.UNKNOWN_SOURCE, "windows", "anything")


def test_nginx_accepts_unencoded_spaces_in_request_target() -> None:
    event = parse_nginx(nginx_line(path="/search?q=<img src=x onerror=alert(1)>"), INGEST_TIME)
    assert event.url_path == "/search?q=<img src=x onerror=alert(1)>"
