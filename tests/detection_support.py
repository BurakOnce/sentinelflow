from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

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
from simulator.simulation import AttackRequest, SimulationPlan, simulate
from streaming.parsing.python_parser import parse_line

BASE = datetime(2026, 9, 28, 9, tzinfo=UTC)
ATTACKER = "36.100.2.3"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36"


def normalized(events: Iterable[LogEvent]) -> list[dict[str, Any]]:
    return [
        parse_line(str(event.source), event.render(), event.timestamp).as_dict() for event in events
    ]


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


def ssh(
    seconds: float,
    kind: SshEventKind,
    user: str = "root",
    ip: str = ATTACKER,
    port: int = 40000,
) -> SshEvent:
    return SshEvent(at(seconds), ip, "bastion-01", 1000 + int(seconds), kind, user, port, 1001)


def ssh_failures(
    count: int, spacing: float, ip: str = ATTACKER, user: str = "root"
) -> list[SshEvent]:
    return [
        ssh(index * spacing, SshEventKind.FAILED_PASSWORD, user, ip, 40000 + index)
        for index in range(count)
    ]


def app_login(
    seconds: float,
    user: str,
    ip: str = ATTACKER,
    result: AuthResult = AuthResult.FAILURE,
    agent: str = CHROME,
) -> AppAuthEvent:
    return AppAuthEvent(
        timestamp=at(seconds),
        src_ip=ip,
        username=user,
        result=result,
        reason=FailureReason.INVALID_PASSWORD if result is AuthResult.FAILURE else None,
        mfa=MfaMethod.PUSH,
        user_agent=agent,
        request_id=f"{int(seconds * 1000):016x}",
    )


def firewall(seconds: float, port: int, ip: str = ATTACKER) -> FirewallEvent:
    return FirewallEvent(
        timestamp=at(seconds),
        src_ip=ip,
        host="fw-edge-01",
        action=FirewallAction.DROP,
        dst_ip="203.0.113.10",
        protocol="TCP",
        src_port=50000 + port % 10000,
        dst_port=port,
        ttl=50,
        length=60,
        packet_id=port,
    )


def request(seconds: float, path: str, agent: str = CHROME, ip: str = ATTACKER) -> HttpRequest:
    return HttpRequest(at(seconds), ip, "GET", path, 200, 512, agent)


def scenario_events(name: str, seed: int = 3, baseline: bool = False) -> list[dict[str, Any]]:
    plan = SimulationPlan(
        start=BASE - timedelta(hours=9),
        end=BASE + timedelta(hours=15),
        seed=seed,
        users=200,
        attacks=(AttackRequest(name),) if name else (),
        baseline=baseline,
    )
    return normalized(record.event for record in simulate(plan))
