from datetime import datetime, timedelta
from random import Random

from simulator.events import (
    AppAuthEvent,
    AuthResult,
    FailureReason,
    FirewallAction,
    FirewallEvent,
    HttpRequest,
    LogEvent,
    MfaMethod,
    SshEvent,
    SshEventKind,
)
from simulator.infrastructure import BASTION_HOST, BASTION_IP, FIREWALL_HOST, PORTAL_IP

LOGIN_PATH = "/api/v1/auth/login"
PORTAL_ORIGIN = "https://portal.sentinelflow.local"


def seconds(value: float) -> timedelta:
    return timedelta(seconds=value)


def ephemeral_port(rng: Random) -> int:
    return rng.randint(32768, 60999)


def request_id(rng: Random) -> str:
    return f"{rng.getrandbits(64):016x}"


def firewall_packet(
    rng: Random,
    timestamp: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    action: FirewallAction,
    protocol: str = "TCP",
) -> FirewallEvent:
    return FirewallEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        host=FIREWALL_HOST,
        action=action,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=ephemeral_port(rng),
        dst_port=dst_port,
        ttl=rng.choice((47, 48, 50, 52, 54, 116, 117, 118)),
        length=rng.choice((52, 60, 64)),
        packet_id=rng.randint(1, 65535),
    )


def portal_login(
    rng: Random,
    timestamp: datetime,
    src_ip: str,
    username: str,
    user_agent: str,
    result: AuthResult,
    reason: FailureReason | None,
    mfa: MfaMethod,
) -> list[LogEvent]:
    status = 200 if result is AuthResult.SUCCESS else 401
    return [
        HttpRequest(
            timestamp=timestamp,
            src_ip=src_ip,
            method="POST",
            path=LOGIN_PATH,
            status=status,
            bytes_sent=rng.randint(380, 420) if status == 200 else rng.randint(60, 75),
            user_agent=user_agent,
            referer=f"{PORTAL_ORIGIN}/login",
        ),
        AppAuthEvent(
            timestamp=timestamp + seconds(rng.uniform(0.005, 0.08)),
            src_ip=src_ip,
            username=username,
            result=result,
            reason=reason,
            mfa=mfa,
            user_agent=user_agent,
            request_id=request_id(rng),
        ),
    ]


def ssh_password_attempt(
    rng: Random,
    timestamp: datetime,
    src_ip: str,
    username: str,
    known_user: bool,
    succeeded: bool,
    pid: int,
    port: int,
    uid: int | None = None,
    host: str = BASTION_HOST,
) -> list[SshEvent]:
    def event(kind: SshEventKind, offset: float, event_uid: int | None = None) -> SshEvent:
        return SshEvent(
            timestamp=timestamp + seconds(offset),
            src_ip=src_ip,
            host=host,
            pid=pid,
            kind=kind,
            username=username,
            port=port,
            uid=event_uid,
        )

    if not known_user:
        return [
            event(SshEventKind.INVALID_USER, 0.0),
            event(SshEventKind.FAILED_PASSWORD_INVALID_USER, rng.uniform(1.5, 2.5)),
        ]
    if succeeded:
        return [
            event(SshEventKind.ACCEPTED_PASSWORD, 0.0),
            event(SshEventKind.SESSION_OPENED, rng.uniform(0.01, 0.05), uid),
        ]
    return [event(SshEventKind.FAILED_PASSWORD, rng.uniform(1.5, 2.5))]


def ssh_connection(rng: Random, timestamp: datetime, src_ip: str) -> FirewallEvent:
    return firewall_packet(rng, timestamp, src_ip, BASTION_IP, 22, FirewallAction.ACCEPT)


def https_connection(rng: Random, timestamp: datetime, src_ip: str) -> FirewallEvent:
    return firewall_packet(rng, timestamp, src_ip, PORTAL_IP, 443, FirewallAction.ACCEPT)
