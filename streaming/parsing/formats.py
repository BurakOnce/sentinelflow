import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
UINT16_MAX = 65535


class ParseErrorCode(StrEnum):
    UNKNOWN_SOURCE = "unknown_source"
    UNRECOGNIZED_FORMAT = "unrecognized_format"
    INVALID_TIMESTAMP = "invalid_timestamp"
    INVALID_JSON = "invalid_json"
    MISSING_FIELD = "missing_field"
    INVALID_FIELD = "invalid_field"
    NUMBER_OUT_OF_RANGE = "number_out_of_range"


@dataclass(frozen=True, slots=True)
class TimestampFormat:
    python: str
    spark: str


@dataclass(frozen=True, slots=True)
class Lookup:
    key: str
    mapping: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class StatusOutcome:
    key: str


Derived = Lookup | StatusOutcome


@dataclass(frozen=True, slots=True)
class LinePattern:
    name: str
    regex: str
    constants: Mapping[str, str]
    captures: Mapping[str, str]
    derived: Mapping[str, Derived] = field(default_factory=dict)

    @property
    def compiled(self) -> re.Pattern[str]:
        return _compile(self.regex)

    @property
    def spark_regex(self) -> str:
        return re.sub(r"\(\?P<\w+>", "(", self.regex)

    def group_index(self, name: str) -> int:
        return self.compiled.groupindex[name]


@dataclass(frozen=True, slots=True)
class RegexFormat:
    source_type: str
    timestamp_key: str
    timestamp_format: TimestampFormat
    null_tokens: frozenset[str]
    patterns: tuple[LinePattern, ...]


@dataclass(frozen=True, slots=True)
class JsonFormat:
    source_type: str
    timestamp_key: str
    timestamp_format: TimestampFormat
    required: tuple[str, ...]
    constants: Mapping[str, str]
    captures: Mapping[str, str]
    ip_keys: tuple[str, ...]
    derived: Mapping[str, Derived] = field(default_factory=dict)


LogFormat = RegexFormat | JsonFormat

_compiled_cache: dict[str, re.Pattern[str]] = {}


def _compile(regex: str) -> re.Pattern[str]:
    if regex not in _compiled_cache:
        _compiled_cache[regex] = re.compile(regex)
    return _compiled_cache[regex]


ISO_MICROS = TimestampFormat("%Y-%m-%dT%H:%M:%S.%f%z", "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX")
SYSLOG_PREFIX = r"^(?P<ts>\S+) (?P<host>\S+) "
SSHD_PREFIX = SYSLOG_PREFIX + r"sshd\[\d+\]: "
SSH_ORIGIN = rf"from (?P<ip>{IPV4}) port (?P<port>\d{{1,5}})"
SSH_LOGIN = {"event_category": "authentication", "event_action": "ssh_login"}

NGINX = RegexFormat(
    source_type="nginx",
    timestamp_key="ts",
    timestamp_format=TimestampFormat("%d/%b/%Y:%H:%M:%S %z", "dd/MMM/yyyy:HH:mm:ss Z"),
    null_tokens=frozenset({"-"}),
    patterns=(
        LinePattern(
            name="nginx_combined",
            regex=(
                rf"^(?P<ip>{IPV4}) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
                r'"(?P<method>[A-Z]{3,10}) (?P<path>[^"]+?) HTTP/\d(?:\.\d)?" '
                r'(?P<status>\d{3}) (?:\d+|-) "[^"]*" "(?P<agent>[^"]*)"$'
            ),
            constants={"event_category": "web", "event_action": "http_request"},
            captures={
                "source_ip": "ip",
                "user_name": "user",
                "http_method": "method",
                "url_path": "path",
                "http_status": "status",
                "user_agent": "agent",
            },
            derived={"event_outcome": StatusOutcome("status")},
        ),
        LinePattern(
            name="nginx_malformed_request",
            regex=(
                rf'^(?P<ip>{IPV4}) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "-" '
                r'(?P<status>\d{3}) (?:\d+|-) "[^"]*" "(?P<agent>[^"]*)"$'
            ),
            constants={"event_category": "web", "event_action": "http_request"},
            captures={
                "source_ip": "ip",
                "user_name": "user",
                "http_status": "status",
                "user_agent": "agent",
            },
            derived={"event_outcome": StatusOutcome("status")},
        ),
    ),
)

SSH = RegexFormat(
    source_type="ssh",
    timestamp_key="ts",
    timestamp_format=ISO_MICROS,
    null_tokens=frozenset(),
    patterns=(
        LinePattern(
            name="ssh_accepted",
            regex=SSHD_PREFIX
            + rf"Accepted (?:password|publickey) for (?P<user>\S+) {SSH_ORIGIN} ssh2(?:: .*)?$",
            constants={**SSH_LOGIN, "event_outcome": "success"},
            captures={
                "host_name": "host",
                "user_name": "user",
                "source_ip": "ip",
                "source_port": "port",
            },
        ),
        LinePattern(
            name="ssh_failed_invalid_user",
            regex=SSHD_PREFIX
            + rf"Failed password for invalid user (?P<user>\S*) {SSH_ORIGIN} ssh2$",
            constants={**SSH_LOGIN, "event_outcome": "failure"},
            captures={
                "host_name": "host",
                "user_name": "user",
                "source_ip": "ip",
                "source_port": "port",
            },
        ),
        LinePattern(
            name="ssh_failed",
            regex=SSHD_PREFIX + rf"Failed password for (?P<user>\S+) {SSH_ORIGIN} ssh2$",
            constants={**SSH_LOGIN, "event_outcome": "failure"},
            captures={
                "host_name": "host",
                "user_name": "user",
                "source_ip": "ip",
                "source_port": "port",
            },
        ),
        LinePattern(
            name="ssh_invalid_user",
            regex=SSHD_PREFIX + rf"Invalid user (?P<user>\S*) {SSH_ORIGIN}$",
            constants={
                "event_category": "authentication",
                "event_action": "ssh_invalid_user",
                "event_outcome": "failure",
            },
            captures={
                "host_name": "host",
                "user_name": "user",
                "source_ip": "ip",
                "source_port": "port",
            },
        ),
        LinePattern(
            name="ssh_session_opened",
            regex=SSHD_PREFIX
            + r"pam_unix\(sshd:session\): session opened for user (?P<user>[^\s(]+)"
            + r"\(uid=\d+\) by \(uid=0\)$",
            constants={
                "event_category": "authentication",
                "event_action": "ssh_session_open",
                "event_outcome": "success",
            },
            captures={"host_name": "host", "user_name": "user"},
        ),
    ),
)

FIREWALL = RegexFormat(
    source_type="firewall",
    timestamp_key="ts",
    timestamp_format=ISO_MICROS,
    null_tokens=frozenset(),
    patterns=(
        LinePattern(
            name="iptables",
            regex=SYSLOG_PREFIX
            + r"kernel: FW ACTION=(?P<action>ACCEPT|DROP|REJECT) IN=\S* OUT=\S* "
            + rf"SRC=(?P<src>{IPV4}) DST=(?P<dst>{IPV4}) .*?PROTO=(?P<proto>TCP|UDP|ICMP)"
            + r"(?: SPT=(?P<spt>\d{1,5}) DPT=(?P<dpt>\d{1,5}))?.*$",
            constants={"event_category": "network"},
            captures={
                "host_name": "host",
                "source_ip": "src",
                "destination_ip": "dst",
                "source_port": "spt",
                "destination_port": "dpt",
            },
            derived={
                "event_action": Lookup(
                    "action",
                    {
                        "ACCEPT": "firewall_accept",
                        "DROP": "firewall_drop",
                        "REJECT": "firewall_reject",
                    },
                ),
                "event_outcome": Lookup(
                    "action", {"ACCEPT": "success", "DROP": "failure", "REJECT": "failure"}
                ),
            },
        ),
    ),
)

APP = JsonFormat(
    source_type="app",
    timestamp_key="timestamp",
    timestamp_format=TimestampFormat("%Y-%m-%dT%H:%M:%S.%f%z", "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"),
    required=("timestamp", "ip", "result"),
    constants={"event_category": "authentication", "event_action": "app_login"},
    captures={
        "source_ip": "ip",
        "user_name": "user",
        "user_agent": "user_agent",
        "host_name": "service",
    },
    ip_keys=("ip",),
    derived={"event_outcome": Lookup("result", {"success": "success", "failure": "failure"})},
)

FORMATS: dict[str, LogFormat] = {fmt.source_type: fmt for fmt in (NGINX, SSH, FIREWALL, APP)}
UINT16_FIELDS = frozenset({"source_port", "destination_port", "http_status"})
