import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from clickhouse_connect.driver.client import Client

from detections.engine.alerts import Alert
from enrichment.geo import GeoLookup
from enrichment.risk import RiskInputs, RiskScore, RiskWeights, score
from enrichment.threat_intel import IntelLookup, Verdict

RECURRENCE_WINDOW = timedelta(hours=24)
RecurrenceCounter = Callable[[str, str, datetime], int]


@dataclass(frozen=True, slots=True)
class AlertContext:
    country_code: str | None
    country: str | None
    city: str | None
    asn: int | None
    as_org: str | None
    is_known_malicious: bool
    abuse_score: int | None
    risk: RiskScore


class BaselineLookup(Protocol):
    def usual_countries(self, users: Sequence[str]) -> dict[str, set[str]]: ...

    def organization_countries(self) -> set[str]: ...


class StaticBaselineLookup:
    def __init__(
        self, users: Mapping[str, set[str]] | None = None, organization: set[str] | None = None
    ) -> None:
        self._users = dict(users or {})
        self._organization = set(organization or ())

    def usual_countries(self, users: Sequence[str]) -> dict[str, set[str]]:
        return {user: self._users[user] for user in users if user in self._users}

    def organization_countries(self) -> set[str]:
        return self._organization


class ClickHouseBaselineLookup:
    def __init__(self, client: Client, cache_seconds: float = 600) -> None:
        self._client = client
        self._cache_seconds = cache_seconds
        self._organization: tuple[float, set[str]] | None = None

    def usual_countries(self, users: Sequence[str]) -> dict[str, set[str]]:
        if not users:
            return {}
        result = self._client.query(
            """
            SELECT user_name, groupUniqArray(country)
            FROM
            (
                SELECT
                    user_name,
                    dictGet('geoip_city', 'country_code', assumeNotNull(source_ip)) AS country,
                    count() AS logins
                FROM events
                WHERE event_category = 'authentication'
                  AND event_outcome = 'success'
                  AND source_ip IS NOT NULL
                  AND user_name IN {users:Array(String)}
                GROUP BY user_name, country
                HAVING logins >= 3 AND country != ''
            )
            GROUP BY user_name
            """,
            parameters={"users": sorted(set(users))},
        )
        return {user: set(countries) for user, countries in result.result_rows}

    def organization_countries(self) -> set[str]:
        now = time.monotonic()
        if self._organization is None or now - self._organization[0] > self._cache_seconds:
            result = self._client.query(
                """
                SELECT country
                FROM
                (
                    SELECT
                        dictGet('geoip_city', 'country_code', assumeNotNull(source_ip)) AS country,
                        count() AS logins,
                        sum(count()) OVER () AS total
                    FROM events
                    WHERE event_category = 'authentication'
                      AND event_outcome = 'success'
                      AND source_ip IS NOT NULL
                    GROUP BY country
                )
                WHERE country != '' AND logins >= 0.02 * total
                """
            )
            self._organization = (now, {row[0] for row in result.result_rows})
        return self._organization[1]


class AlertEnricher:
    def __init__(
        self,
        geo: GeoLookup,
        intel: IntelLookup,
        baseline: BaselineLookup,
        weights: RiskWeights,
        recurrence: RecurrenceCounter,
    ) -> None:
        self._geo = geo
        self._intel = intel
        self._baseline = baseline
        self._weights = weights
        self._recurrence = recurrence

    def enrich(self, alerts: Sequence[Alert]) -> list[tuple[Alert, AlertContext]]:
        ips = sorted({alert.source_ip for alert in alerts if alert.source_ip})
        locations = self._geo.locate(ips)
        verdicts = self._intel.verdicts(ips)
        users = sorted({alert.user_name for alert in alerts if alert.user_name})
        usual = self._baseline.usual_countries(users)
        organization = self._baseline.organization_countries()
        enriched = []
        for alert in alerts:
            location = locations.get(alert.source_ip or "")
            verdict = verdicts.get(alert.source_ip or "", Verdict())
            country = location.country_code if location else None
            if country is None:
                foreign = False
            elif alert.user_name and usual.get(alert.user_name):
                foreign = country not in usual[alert.user_name]
            else:
                foreign = bool(organization) and country not in organization
            recent = self._recurrence(
                alert.entity_type, alert.entity, alert.first_seen - RECURRENCE_WINDOW
            )
            risk = score(
                RiskInputs(
                    level=alert.level,
                    is_known_malicious=verdict.is_malicious,
                    abuse_score=verdict.abuse_score,
                    foreign_country=foreign,
                    successful_login=alert.has_success,
                    recent_alerts=max(recent - 1, 0),
                ),
                self._weights,
            )
            enriched.append(
                (
                    alert,
                    AlertContext(
                        country_code=country,
                        country=location.country if location else None,
                        city=location.city if location else None,
                        asn=location.asn if location else None,
                        as_org=location.as_org if location else None,
                        is_known_malicious=verdict.is_malicious,
                        abuse_score=verdict.abuse_score,
                        risk=risk,
                    ),
                )
            )
        return enriched
