import heapq
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime, timedelta
from random import Random

from simulator.activity import (
    PORTAL_ORIGIN,
    ephemeral_port,
    firewall_packet,
    https_connection,
    portal_login,
    seconds,
    ssh_connection,
    ssh_password_attempt,
)
from simulator.events import (
    AuthResult,
    FailureReason,
    FirewallAction,
    HttpRequest,
    LogEvent,
    MfaMethod,
    SshEvent,
    SshEventKind,
)
from simulator.geo import COUNTRIES
from simulator.infrastructure import (
    BASTION_HOST,
    BASTION_INTERNAL_IP,
    CRAWLER_USER_AGENTS,
    INTERNAL_SSH_HOSTS,
    PUBLIC_ADDRESSES,
)
from simulator.population import User

ONE_DAY = timedelta(days=1)
PORTAL_PAGES: tuple[tuple[str, int, int], ...] = (
    ("/dashboard", 18_000, 26_000),
    ("/reports", 22_000, 41_000),
    ("/tickets", 15_000, 30_000),
    ("/profile", 9_000, 12_000),
    ("/api/v1/notifications", 300, 2_400),
    ("/api/v1/tasks", 1_200, 9_800),
    ("/api/v1/reports/summary", 2_000, 14_000),
    ("/api/v1/tickets?status=open", 1_500, 12_000),
)
PAGE_WEIGHTS = (20, 10, 12, 3, 25, 15, 8, 7)
STATIC_ASSETS: tuple[tuple[str, int], ...] = (
    ("/static/js/app.4f9c2e1b.js", 412_331),
    ("/static/css/app.8d1a7c33.css", 58_904),
    ("/static/img/logo.svg", 3_217),
)
CRAWLER_PATHS = ("/", "/login", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/about")
NOISE_TCP_PORTS = (23, 445, 3389, 5900, 8080, 1433, 3306, 6379, 2323, 5555, 81, 8443, 9200, 27017)
NOISE_UDP_PORTS = (53, 123, 161, 1900, 5060)
NOISE_PER_HOUR = 180
CRAWLS_PER_HOUR = 12
MONITOR_IP = "10.20.0.5"
MONITOR_AGENT = "Uptime-Kuma/2.0.0"


class BaselineGenerator:
    def __init__(self, users: Sequence[User], seed: int) -> None:
        self._users = users
        self._seed = seed

    def events(self, start: datetime, end: datetime) -> Iterator[LogEvent]:
        pending: list[tuple[datetime, int, LogEvent]] = []
        sequence = 0
        day = start.replace(hour=0, minute=0, second=0, microsecond=0)
        while day < end:
            for event in self._day(day):
                if start <= event.timestamp < end:
                    heapq.heappush(pending, (event.timestamp, sequence, event))
                    sequence += 1
            boundary = day + ONE_DAY
            while pending and pending[0][0] < boundary:
                yield heapq.heappop(pending)[2]
            day = boundary
        while pending:
            yield heapq.heappop(pending)[2]

    def _rng(self, *parts: object) -> Random:
        return Random(":".join(str(part) for part in (self._seed, "baseline", *parts)))

    def _day(self, day: datetime) -> Iterator[LogEvent]:
        for user in self._users:
            yield from self._user_day(user, day)
        yield from self._internet_noise(day)
        yield from self._crawlers(day)
        yield from self._uptime_checks(day)

    def _user_day(self, user: User, day: datetime) -> Iterator[LogEvent]:
        rng = self._rng(user.username, day.date())
        weekend = day.weekday() >= 5
        if rng.random() < (0.85 if weekend else 0.04):
            return
        session_count = max(1, round(rng.gauss(user.sessions_per_day, 0.8)))
        for _ in range(session_count):
            yield from self._web_session(rng, user, self._at_local_hour(day, user, rng))
        if user.ssh_access and not weekend:
            for _ in range(rng.randint(0, 4)):
                yield from self._ssh_session(rng, user, self._at_local_hour(day, user, rng))

    def _at_local_hour(self, day: datetime, user: User, rng: Random) -> datetime:
        roll = rng.random()
        if roll < 0.88:
            local_hour = rng.uniform(user.work_start_hour, user.work_end_hour - 0.5)
        elif roll < 0.97:
            local_hour = rng.uniform(19.0, 23.5)
        else:
            local_hour = rng.uniform(0.0, 6.0)
        return day + timedelta(hours=(local_hour - user.utc_offset_hours) % 24)

    def _web_session(self, rng: Random, user: User, start: datetime) -> Iterator[LogEvent]:
        on_mobile = user.mobile_agent is not None and rng.random() < 0.2
        ip = user.mobile_ip if on_mobile else user.home_ip
        agent = user.mobile_agent if on_mobile and user.mobile_agent else user.desktop_agent
        yield https_connection(rng, start - seconds(0.05), ip)
        now = start
        yield self._page(rng, now, ip, agent, "/login", 5_800, referer="-")
        yield from self._assets(rng, now, ip, agent)
        now += seconds(rng.uniform(4, 15))
        if rng.random() < user.typo_rate:
            yield from portal_login(
                rng,
                now,
                ip,
                user.username,
                agent,
                AuthResult.FAILURE,
                FailureReason.INVALID_PASSWORD,
                user.mfa,
            )
            now += seconds(rng.uniform(5, 20))
        if user.mfa is not MfaMethod.NONE and rng.random() < 0.02:
            yield from portal_login(
                rng,
                now,
                ip,
                user.username,
                agent,
                AuthResult.FAILURE,
                FailureReason.MFA_FAILED,
                user.mfa,
            )
            now += seconds(rng.uniform(20, 60))
        yield from portal_login(
            rng, now, ip, user.username, agent, AuthResult.SUCCESS, None, user.mfa
        )
        for _ in range(rng.randint(4, 30)):
            now += seconds(rng.expovariate(1 / 40))
            path, low, high = rng.choices(PORTAL_PAGES, PAGE_WEIGHTS)[0]
            yield self._page(rng, now, ip, agent, path, rng.randint(low, high))

    def _page(
        self,
        rng: Random,
        timestamp: datetime,
        ip: str,
        agent: str,
        path: str,
        size: int,
        referer: str | None = None,
    ) -> HttpRequest:
        status = rng.choices((200, 304, 404, 500), (960, 25, 10, 5))[0]
        return HttpRequest(
            timestamp=timestamp,
            src_ip=ip,
            method="GET",
            path=path,
            status=status,
            bytes_sent=size if status == 200 else rng.randint(0, 600),
            user_agent=agent,
            referer=f"{PORTAL_ORIGIN}/dashboard" if referer is None else referer,
        )

    def _assets(
        self, rng: Random, timestamp: datetime, ip: str, agent: str
    ) -> Iterable[HttpRequest]:
        cached = rng.random() < 0.7
        for offset, (path, size) in enumerate(STATIC_ASSETS, start=1):
            yield HttpRequest(
                timestamp=timestamp + seconds(0.05 * offset + rng.uniform(0, 0.03)),
                src_ip=ip,
                method="GET",
                path=path,
                status=304 if cached else 200,
                bytes_sent=0 if cached else size,
                user_agent=agent,
                referer=f"{PORTAL_ORIGIN}/login",
            )

    def _ssh_session(self, rng: Random, user: User, start: datetime) -> Iterator[LogEvent]:
        yield ssh_connection(rng, start - seconds(0.02), user.home_ip)
        pid, port = rng.randint(20_000, 65_000), ephemeral_port(rng)
        if rng.random() < 0.85:
            yield from self._publickey_login(user, start, user.home_ip, BASTION_HOST, pid, port)
        else:
            now = start
            if rng.random() < user.typo_rate * 2:
                yield from ssh_password_attempt(
                    rng, now, user.home_ip, user.username, True, False, pid, port
                )
                now += seconds(rng.uniform(3, 8))
            yield from ssh_password_attempt(
                rng, now, user.home_ip, user.username, True, True, pid, port, user.uid
            )
        if rng.random() < 0.5:
            hop = start + seconds(rng.uniform(30, 300))
            yield from self._publickey_login(
                user,
                hop,
                BASTION_INTERNAL_IP,
                rng.choice(INTERNAL_SSH_HOSTS),
                rng.randint(20_000, 65_000),
                ephemeral_port(rng),
            )

    def _publickey_login(
        self, user: User, timestamp: datetime, src_ip: str, host: str, pid: int, port: int
    ) -> Iterator[SshEvent]:
        for kind, offset in (
            (SshEventKind.ACCEPTED_PUBLICKEY, 0.0),
            (SshEventKind.SESSION_OPENED, 0.02),
        ):
            yield SshEvent(
                timestamp=timestamp + seconds(offset),
                src_ip=src_ip,
                host=host,
                pid=pid,
                kind=kind,
                username=user.username,
                port=port,
                uid=user.uid,
                key_fingerprint=user.ssh_key_fingerprint,
            )

    def _internet_noise(self, day: datetime) -> Iterator[LogEvent]:
        rng = self._rng("noise", day.date())
        countries = list(COUNTRIES.values())
        for _ in range(NOISE_PER_HOUR * 24):
            timestamp = day + seconds(rng.uniform(0, ONE_DAY.total_seconds()))
            udp = rng.random() < 0.15
            yield firewall_packet(
                rng,
                timestamp,
                rng.choice(countries).random_ip(rng),
                rng.choice(PUBLIC_ADDRESSES),
                rng.choice(NOISE_UDP_PORTS if udp else NOISE_TCP_PORTS),
                FirewallAction.DROP,
                "UDP" if udp else "TCP",
            )

    def _crawlers(self, day: datetime) -> Iterator[LogEvent]:
        rng = self._rng("crawlers", day.date())
        crawler_ips = [COUNTRIES["US"].random_ip(rng) for _ in range(6)]
        for _ in range(CRAWLS_PER_HOUR * 24):
            path = rng.choice(CRAWLER_PATHS)
            status = 404 if path == "/about" else 200
            yield HttpRequest(
                timestamp=day + seconds(rng.uniform(0, ONE_DAY.total_seconds())),
                src_ip=rng.choice(crawler_ips),
                method="GET",
                path=path,
                status=status,
                bytes_sent=rng.randint(200, 6_000) if status == 200 else 153,
                user_agent=rng.choice(CRAWLER_USER_AGENTS),
            )

    def _uptime_checks(self, day: datetime) -> Iterator[LogEvent]:
        rng = self._rng("uptime", day.date())
        for minute in range(24 * 60):
            yield HttpRequest(
                timestamp=day + timedelta(minutes=minute, seconds=rng.uniform(0, 1)),
                src_ip=MONITOR_IP,
                method="GET",
                path="/healthz",
                status=200,
                bytes_sent=2,
                user_agent=MONITOR_AGENT,
            )
