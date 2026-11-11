import json
import re
from datetime import UTC, datetime

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

TIMESTAMP = datetime(2026, 9, 30, 14, 2, 11, 123456, tzinfo=UTC)
NGINX_COMBINED = re.compile(
    r'^(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"$'
)
SYSLOG_SSHD = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}T\S+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<message>.+)$"
)
IPTABLES_FIELD = re.compile(r"(?P<key>[A-Z]+)=(?P<value>\S*)")


def ssh_event(kind: SshEventKind, username: str = "ayse.yilmaz") -> SshEvent:
    return SshEvent(TIMESTAMP, "85.100.1.2", "bastion-01", 4242, kind, username, 51514, 1001, "AbC")


def test_nginx_line_follows_combined_format() -> None:
    line = HttpRequest(
        TIMESTAMP, "78.160.4.5", "GET", "/dashboard", 200, 1234, "curl/8.5.0", "-"
    ).render()
    match = NGINX_COMBINED.match(line)
    assert match is not None
    assert match["time"] == "30/Sep/2026:14:02:11 +0000"
    assert match["request"] == "GET /dashboard HTTP/1.1"
    assert match["status"] == "200"


def test_nginx_escapes_quotes_like_nginx() -> None:
    line = HttpRequest(
        TIMESTAMP, "1.2.3.4", "GET", '/search?q="><svg/onload=alert(1)>', 400, 10, "x"
    ).render()
    match = NGINX_COMBINED.match(line)
    assert match is not None
    assert "\\x22" in match["request"]


def test_sshd_messages_match_openssh_wording() -> None:
    expected = {
        SshEventKind.ACCEPTED_PASSWORD: "Accepted password for ayse.yilmaz from 85.100.1.2 "
        "port 51514 ssh2",
        SshEventKind.FAILED_PASSWORD: "Failed password for ayse.yilmaz from 85.100.1.2 "
        "port 51514 ssh2",
        SshEventKind.INVALID_USER: "Invalid user ayse.yilmaz from 85.100.1.2 port 51514",
        SshEventKind.FAILED_PASSWORD_INVALID_USER: "Failed password for invalid user "
        "ayse.yilmaz from 85.100.1.2 port 51514 ssh2",
    }
    for kind, message in expected.items():
        match = SYSLOG_SSHD.match(ssh_event(kind).render())
        assert match is not None
        assert match["message"] == message
        assert datetime.fromisoformat(match["time"]) == TIMESTAMP


def test_firewall_line_exposes_iptables_fields() -> None:
    line = FirewallEvent(
        timestamp=TIMESTAMP,
        src_ip="36.100.2.3",
        host="fw-edge-01",
        action=FirewallAction.DROP,
        dst_ip="203.0.113.10",
        protocol="TCP",
        src_port=40000,
        dst_port=3389,
        ttl=50,
        length=60,
        packet_id=777,
    ).render()
    fields = {match["key"]: match["value"] for match in IPTABLES_FIELD.finditer(line)}
    assert fields["ACTION"] == "DROP"
    assert fields["SRC"] == "36.100.2.3"
    assert fields["DST"] == "203.0.113.10"
    assert fields["DPT"] == "3389"
    assert fields["PROTO"] == "TCP"


def test_app_auth_line_is_json_with_required_fields() -> None:
    line = AppAuthEvent(
        timestamp=TIMESTAMP,
        src_ip="88.230.1.1",
        username="mehmet.kaya",
        result=AuthResult.FAILURE,
        reason=FailureReason.INVALID_PASSWORD,
        mfa=MfaMethod.PUSH,
        user_agent="Mozilla/5.0",
        request_id="abc123",
    ).render()
    payload = json.loads(line)
    assert payload["timestamp"] == "2026-09-30T14:02:11.123Z"
    assert payload["user"] == "mehmet.kaya"
    assert payload["ip"] == "88.230.1.1"
    assert payload["result"] == "failure"
    assert payload["user_agent"] == "Mozilla/5.0"
    assert payload["mfa"] == "push"
