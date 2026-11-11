import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import ClassVar, Self

MONTH_ABBREVIATIONS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


class Source(StrEnum):
    NGINX = "nginx"
    SSH = "ssh"
    FIREWALL = "firewall"
    APP = "app"


class SshEventKind(StrEnum):
    ACCEPTED_PASSWORD = "accepted_password"
    ACCEPTED_PUBLICKEY = "accepted_publickey"
    FAILED_PASSWORD = "failed_password"
    FAILED_PASSWORD_INVALID_USER = "failed_password_invalid_user"
    INVALID_USER = "invalid_user"
    SESSION_OPENED = "session_opened"


class FirewallAction(StrEnum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"


class AuthResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class FailureReason(StrEnum):
    INVALID_PASSWORD = "invalid_password"
    UNKNOWN_USER = "unknown_user"
    MFA_FAILED = "mfa_failed"


class MfaMethod(StrEnum):
    PUSH = "push"
    TOTP = "totp"
    NONE = "none"


def rfc3339(timestamp: datetime) -> str:
    return timestamp.astimezone(UTC).isoformat(timespec="microseconds")


def nginx_time(timestamp: datetime) -> str:
    utc = timestamp.astimezone(UTC)
    month = MONTH_ABBREVIATIONS[utc.month - 1]
    return f"{utc.day:02d}/{month}/{utc.year}:{utc:%H:%M:%S} +0000"


def iso_millis(timestamp: datetime) -> str:
    utc = timestamp.astimezone(UTC)
    return f"{utc:%Y-%m-%dT%H:%M:%S}.{utc.microsecond // 1000:03d}Z"


def nginx_escape(value: str) -> str:
    return "".join(
        f"\\x{ord(char):02X}" if char in '"\\' or not 32 <= ord(char) <= 126 else char
        for char in value
    )


@dataclass(frozen=True, slots=True)
class LogEvent(ABC):
    source: ClassVar[Source]

    timestamp: datetime
    src_ip: str

    @property
    def user(self) -> str | None:
        return None

    @abstractmethod
    def render(self) -> str: ...

    def shifted(self, delta: timedelta) -> Self:
        return replace(self, timestamp=self.timestamp + delta)


@dataclass(frozen=True, slots=True)
class HttpRequest(LogEvent):
    source: ClassVar[Source] = Source.NGINX

    method: str
    path: str
    status: int
    bytes_sent: int
    user_agent: str
    referer: str = "-"
    protocol: str = "HTTP/1.1"

    def render(self) -> str:
        request = nginx_escape(f"{self.method} {self.path} {self.protocol}")
        return (
            f"{self.src_ip} - - [{nginx_time(self.timestamp)}] "
            f'"{request}" {self.status} {self.bytes_sent} '
            f'"{nginx_escape(self.referer)}" "{nginx_escape(self.user_agent)}"'
        )


@dataclass(frozen=True, slots=True)
class SshEvent(LogEvent):
    source: ClassVar[Source] = Source.SSH

    host: str
    pid: int
    kind: SshEventKind
    username: str
    port: int
    uid: int | None = None
    key_fingerprint: str | None = None

    @property
    def user(self) -> str | None:
        return self.username

    def _message(self) -> str:
        origin = f"from {self.src_ip} port {self.port}"
        match self.kind:
            case SshEventKind.ACCEPTED_PASSWORD:
                return f"Accepted password for {self.username} {origin} ssh2"
            case SshEventKind.ACCEPTED_PUBLICKEY:
                return (
                    f"Accepted publickey for {self.username} {origin} ssh2: "
                    f"ED25519 SHA256:{self.key_fingerprint}"
                )
            case SshEventKind.FAILED_PASSWORD:
                return f"Failed password for {self.username} {origin} ssh2"
            case SshEventKind.FAILED_PASSWORD_INVALID_USER:
                return f"Failed password for invalid user {self.username} {origin} ssh2"
            case SshEventKind.INVALID_USER:
                return f"Invalid user {self.username} {origin}"
            case SshEventKind.SESSION_OPENED:
                return (
                    f"pam_unix(sshd:session): session opened for user "
                    f"{self.username}(uid={self.uid}) by (uid=0)"
                )

    def render(self) -> str:
        return f"{rfc3339(self.timestamp)} {self.host} sshd[{self.pid}]: {self._message()}"


@dataclass(frozen=True, slots=True)
class FirewallEvent(LogEvent):
    source: ClassVar[Source] = Source.FIREWALL

    host: str
    action: FirewallAction
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    ttl: int
    length: int
    packet_id: int

    def render(self) -> str:
        out_interface = "eth1" if self.action is FirewallAction.ACCEPT else ""
        header = (
            f"{rfc3339(self.timestamp)} {self.host} kernel: FW ACTION={self.action} "
            f"IN=eth0 OUT={out_interface} SRC={self.src_ip} DST={self.dst_ip} "
            f"LEN={self.length} TOS=0x00 PREC=0x00 TTL={self.ttl} ID={self.packet_id}"
        )
        if self.protocol == "UDP":
            return (
                f"{header} PROTO=UDP SPT={self.src_port} DPT={self.dst_port} LEN={self.length - 20}"
            )
        return (
            f"{header} DF PROTO=TCP SPT={self.src_port} DPT={self.dst_port} "
            "WINDOW=64240 RES=0x00 SYN URGP=0"
        )


@dataclass(frozen=True, slots=True)
class AppAuthEvent(LogEvent):
    source: ClassVar[Source] = Source.APP

    username: str
    result: AuthResult
    reason: FailureReason | None
    mfa: MfaMethod
    user_agent: str
    request_id: str

    @property
    def user(self) -> str | None:
        return self.username

    def render(self) -> str:
        return json.dumps(
            {
                "timestamp": iso_millis(self.timestamp),
                "level": "info" if self.result is AuthResult.SUCCESS else "warn",
                "service": "portal-auth",
                "event": "login",
                "request_id": self.request_id,
                "user": self.username,
                "ip": self.src_ip,
                "result": str(self.result),
                "reason": None if self.reason is None else str(self.reason),
                "mfa": str(self.mfa),
                "user_agent": self.user_agent,
            },
            separators=(",", ":"),
            ensure_ascii=False,
        )
