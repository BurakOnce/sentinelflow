import csv
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Protocol

from clickhouse_connect.driver.client import Client

from enrichment.geo import FIXTURE_DIR

THREAT_FIXTURE = FIXTURE_DIR / "threat_intel.csv"
FIREHOL_LEVEL1_URL = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
)
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
HttpGet = Callable[[str, dict[str, str]], tuple[int, dict[str, str], bytes]]
logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Indicator:
    network: str
    provider: str
    is_malicious: bool
    abuse_score: int | None
    categories: tuple[str, ...]
    ttl: timedelta


@dataclass(frozen=True, slots=True)
class Verdict:
    is_malicious: bool = False
    abuse_score: int | None = None
    providers: tuple[str, ...] = ()


class FeedProvider(Protocol):
    name: str

    def fetch(self) -> list[Indicator]: ...


class LookupProvider(Protocol):
    name: str

    def lookup(self, ips: Sequence[str]) -> list[Indicator]: ...


def urllib_get(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


class FixtureProvider:
    name = "fixture"

    def __init__(self, path: Path = THREAT_FIXTURE, ttl: timedelta = timedelta(days=7)) -> None:
        self._path = path
        self._ttl = ttl

    def fetch(self) -> list[Indicator]:
        with self._path.open(encoding="utf-8", newline="") as handle:
            return [
                Indicator(
                    network=str(IPv4Network(row["network"], strict=False)),
                    provider=self.name,
                    is_malicious=True,
                    abuse_score=int(row["abuse_score"]),
                    categories=tuple(row["categories"].split("|")),
                    ttl=self._ttl,
                )
                for row in csv.DictReader(handle)
            ]


class BlocklistFeedProvider:
    def __init__(
        self,
        name: str = "firehol_level1",
        url: str = FIREHOL_LEVEL1_URL,
        ttl: timedelta = timedelta(days=2),
        http_get: HttpGet = urllib_get,
    ) -> None:
        self.name = name
        self._url = url
        self._ttl = ttl
        self._http_get = http_get

    def fetch(self) -> list[Indicator]:
        status, _, body = self._http_get(self._url, {"User-Agent": "sentinelflow"})
        if status != 200:
            raise RuntimeError(f"{self.name} feed returned HTTP {status}")
        indicators = []
        for line in body.decode("utf-8").splitlines():
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                network = IPv4Network(entry, strict=False)
            except ValueError:
                continue
            if network.is_private or network.prefixlen < 8:
                continue
            indicators.append(
                Indicator(str(network), self.name, True, None, ("blocklist",), self._ttl)
            )
        return indicators


@dataclass(slots=True)
class RateLimiter:
    per_minute: int
    per_day: int
    clock: Callable[[], float] = time.monotonic
    _minute: list[float] = field(default_factory=list)
    _day: list[float] = field(default_factory=list)
    _blocked_until: float = 0.0

    def acquire(self) -> bool:
        now = self.clock()
        if now < self._blocked_until:
            return False
        self._minute = [moment for moment in self._minute if now - moment < 60]
        self._day = [moment for moment in self._day if now - moment < 86_400]
        if len(self._minute) >= self.per_minute or len(self._day) >= self.per_day:
            return False
        self._minute.append(now)
        self._day.append(now)
        return True

    def back_off(self, seconds: float) -> None:
        self._blocked_until = self.clock() + seconds


class AbuseIpDbProvider:
    name = "abuseipdb"

    def __init__(
        self,
        api_key: str,
        limiter: RateLimiter | None = None,
        malicious_threshold: int = 50,
        ttl: timedelta = timedelta(hours=24),
        http_get: HttpGet = urllib_get,
    ) -> None:
        self._api_key = api_key
        self._limiter = limiter or RateLimiter(per_minute=30, per_day=900)
        self._threshold = malicious_threshold
        self._ttl = ttl
        self._http_get = http_get

    def lookup(self, ips: Sequence[str]) -> list[Indicator]:
        indicators = []
        for ip in ips:
            if IPv4Address(ip).is_private or not self._limiter.acquire():
                continue
            query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
            status, headers, body = self._http_get(
                f"{ABUSEIPDB_URL}?{query}", {"Key": self._api_key, "Accept": "application/json"}
            )
            if status == 429:
                self._limiter.back_off(float(headers.get("Retry-After", "60")))
                logger.warning("abuseipdb rate limit reached, backing off")
                break
            if status != 200:
                logger.warning("abuseipdb returned HTTP %s for %s", status, ip)
                continue
            data = json.loads(body)["data"]
            score = int(data.get("abuseConfidenceScore", 0))
            indicators.append(
                Indicator(
                    f"{ip}/32",
                    self.name,
                    score >= self._threshold,
                    score,
                    ("reputation",),
                    self._ttl,
                )
            )
        return indicators


INDICATOR_COLUMNS = (
    "network",
    "provider",
    "is_malicious",
    "abuse_score",
    "categories",
    "fetched_at",
    "expires_at",
)


class ThreatIntelStore:
    def __init__(self, client: Client) -> None:
        self._client = client

    def save(self, indicators: Sequence[Indicator], now: datetime | None = None) -> int:
        fetched = (now or datetime.now(UTC)).replace(microsecond=0)
        rows = [
            [
                item.network,
                item.provider,
                int(item.is_malicious),
                item.abuse_score,
                list(item.categories),
                fetched,
                fetched + item.ttl,
            ]
            for item in indicators
        ]
        if rows:
            self._client.insert("threat_intel", rows, column_names=list(INDICATOR_COLUMNS))
        return len(rows)

    def reload(self) -> None:
        self._client.command("SYSTEM RELOAD DICTIONARY threat_intel_networks")

    def cached(self, provider: str, ips: Sequence[str]) -> set[str]:
        if not ips:
            return set()
        result = self._client.query(
            "SELECT network FROM threat_intel FINAL "
            "WHERE provider = {provider:String} AND network IN {networks:Array(String)} "
            "AND expires_at > now()",
            parameters={"provider": provider, "networks": [f"{ip}/32" for ip in ips]},
        )
        return {row[0].removesuffix("/32") for row in result.result_rows}

    def verdicts(self, ips: Sequence[str]) -> dict[str, Verdict]:
        if not ips:
            return {}
        result = self._client.query(
            """
            SELECT
                ip,
                dictGet('threat_intel_networks', 'is_malicious', toIPv4(ip)),
                dictGet('threat_intel_networks', 'abuse_score', toIPv4(ip)),
                dictGet('threat_intel_networks', 'providers', toIPv4(ip))
            FROM (SELECT arrayJoin({ips:Array(String)}) AS ip)
            WHERE dictHas('threat_intel_networks', toIPv4(ip))
            """,
            parameters={"ips": list(ips)},
        )
        return {
            ip: Verdict(
                bool(malicious),
                None if score < 0 else int(score),
                tuple(filter(None, providers.split(","))),
            )
            for ip, malicious, score, providers in result.result_rows
        }


class IntelLookup(Protocol):
    def verdicts(self, ips: Sequence[str]) -> dict[str, Verdict]: ...


class IntelStore(IntelLookup, Protocol):
    def save(self, indicators: Sequence[Indicator], now: datetime | None = None) -> int: ...

    def reload(self) -> None: ...

    def cached(self, provider: str, ips: Sequence[str]) -> set[str]: ...


def merge_verdicts(first: Verdict, second: Verdict) -> Verdict:
    scores = [score for score in (first.abuse_score, second.abuse_score) if score is not None]
    return Verdict(
        first.is_malicious or second.is_malicious,
        max(scores) if scores else None,
        tuple(sorted({*first.providers, *second.providers})),
    )


def indicator_verdict(indicator: Indicator) -> Verdict:
    return Verdict(indicator.is_malicious, indicator.abuse_score, (indicator.provider,))


class ThreatIntelService:
    def __init__(
        self,
        store: IntelStore,
        feeds: Sequence[FeedProvider] = (),
        lookups: Sequence[LookupProvider] = (),
    ) -> None:
        self._store = store
        self._feeds = feeds
        self._lookups = lookups

    def refresh_feeds(self) -> dict[str, int]:
        counts = {}
        for feed in self._feeds:
            counts[feed.name] = self._store.save(feed.fetch())
        self._store.reload()
        return counts

    def verdicts(self, ips: Sequence[str]) -> dict[str, Verdict]:
        public = sorted({ip for ip in ips if not IPv4Address(ip).is_private})
        results = self._store.verdicts(public)
        for provider in self._lookups:
            cached = self._store.cached(provider.name, public)
            missing = [ip for ip in public if ip not in cached]
            fresh = provider.lookup(missing)
            self._store.save(fresh)
            for indicator in fresh:
                ip = indicator.network.removesuffix("/32")
                results[ip] = merge_verdicts(
                    results.get(ip, Verdict()), indicator_verdict(indicator)
                )
        return results
