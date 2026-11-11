import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from detections.engine.alerts import Alert
from enrichment.alert_enrichment import AlertEnricher, StaticBaselineLookup
from enrichment.geo import NetworkTableGeoLookup, haversine_km
from enrichment.risk import RiskInputs, RiskWeights, load_weights, score
from enrichment.threat_intel import (
    AbuseIpDbProvider,
    BlocklistFeedProvider,
    FixtureProvider,
    Indicator,
    RateLimiter,
    ThreatIntelService,
    Verdict,
)

GEO = NetworkTableGeoLookup.from_fixtures()
NOW = datetime(2026, 9, 28, 12, tzinfo=UTC)


class FakeHttp:
    def __init__(self, responses: list[tuple[int, dict[str, str], bytes]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, str]]] = []

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        self.calls.append((url, headers))
        return self.responses.pop(0) if self.responses else (200, {}, b"")


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class MemoryIntelStore:
    def __init__(self, verdicts: dict[str, Verdict] | None = None) -> None:
        self.saved: list[Indicator] = []
        self._verdicts = verdicts or {}
        self.reloads = 0

    def save(self, indicators: Sequence[Indicator], now: datetime | None = None) -> int:
        self.saved.extend(indicators)
        return len(indicators)

    def reload(self) -> None:
        self.reloads += 1

    def cached(self, provider: str, ips: Sequence[str]) -> set[str]:
        return {
            item.network.removesuffix("/32") for item in self.saved if item.provider == provider
        } & set(ips)

    def verdicts(self, ips: Sequence[str]) -> dict[str, Verdict]:
        return {ip: verdict for ip, verdict in self._verdicts.items() if ip in ips}


def abuse_response(ip: str, score_value: int) -> tuple[int, dict[str, str], bytes]:
    body = {"data": {"ipAddress": ip, "abuseConfidenceScore": score_value}}
    return 200, {}, json.dumps(body).encode()


def test_fixture_locations_match_simulator_blocks() -> None:
    located = GEO.locate(["78.160.1.1", "36.100.2.3", "10.0.0.1", "203.0.113.10", "bad"])
    assert located["78.160.1.1"].country_code == "TR"
    assert located["78.160.1.1"].asn == 9121
    assert located["36.100.2.3"].country_code == "CN"
    assert set(located) == {"78.160.1.1", "36.100.2.3"}


def test_haversine_distance_is_plausible() -> None:
    istanbul, new_york = (
        GEO.locate(["78.160.1.1"])["78.160.1.1"],
        GEO.locate(["73.0.1.1"])["73.0.1.1"],
    )
    assert 8000 < haversine_km(istanbul, new_york) < 8200


def test_fixture_provider_flags_part_of_hostile_space() -> None:
    indicators = FixtureProvider().fetch()
    assert indicators
    assert all(item.is_malicious and item.abuse_score for item in indicators)
    assert {item.provider for item in indicators} == {"fixture"}


def test_blocklist_feed_parses_netset_and_skips_noise() -> None:
    body = b"# comment\n1.2.3.0/24\n10.0.0.0/8\n0.0.0.0/0\n\n5.6.7.8 # inline\nnot-an-ip\n"
    provider = BlocklistFeedProvider(http_get=FakeHttp([(200, {}, body)]))
    assert [item.network for item in provider.fetch()] == ["1.2.3.0/24", "5.6.7.8/32"]


def test_blocklist_feed_raises_on_http_error() -> None:
    provider = BlocklistFeedProvider(http_get=FakeHttp([(503, {}, b"")]))
    with pytest.raises(RuntimeError, match="HTTP 503"):
        provider.fetch()


def test_abuseipdb_scores_and_skips_private_addresses() -> None:
    http = FakeHttp([abuse_response("36.1.1.1", 90), abuse_response("73.1.1.1", 10)])
    provider = AbuseIpDbProvider("key", http_get=http)
    indicators = provider.lookup(["36.1.1.1", "10.0.0.1", "73.1.1.1"])
    assert [(item.network, item.is_malicious, item.abuse_score) for item in indicators] == [
        ("36.1.1.1/32", True, 90),
        ("73.1.1.1/32", False, 10),
    ]
    assert all(headers["Key"] == "key" for _, headers in http.calls)
    assert len(http.calls) == 2


def test_abuseipdb_respects_rate_limit_and_backs_off_on_429() -> None:
    clock = FakeClock()
    limiter = RateLimiter(per_minute=2, per_day=100, clock=clock)
    http = FakeHttp([abuse_response("36.1.1.1", 50), (429, {"Retry-After": "120"}, b"")])
    provider = AbuseIpDbProvider("key", limiter=limiter, http_get=http)
    assert len(provider.lookup(["36.1.1.1", "36.1.1.2", "36.1.1.3"])) == 1
    assert len(http.calls) == 2
    clock.now = 90
    assert provider.lookup(["36.1.1.4"]) == []
    assert len(http.calls) == 2
    clock.now = 200
    http.responses.append(abuse_response("36.1.1.4", 5))
    assert len(provider.lookup(["36.1.1.4"])) == 1


def test_rate_limiter_enforces_daily_quota() -> None:
    clock = FakeClock()
    limiter = RateLimiter(per_minute=100, per_day=3, clock=clock)
    assert [limiter.acquire() for _ in range(4)] == [True, True, True, False]
    clock.now = 86_401
    assert limiter.acquire()


def test_service_caches_lookups_and_merges_verdicts() -> None:
    store = MemoryIntelStore({"36.1.1.1": Verdict(True, None, ("fixture",))})
    http = FakeHttp([abuse_response("36.1.1.1", 80), abuse_response("73.1.1.1", 0)])
    service = ThreatIntelService(store, lookups=[AbuseIpDbProvider("key", http_get=http)])
    first = service.verdicts(["36.1.1.1", "73.1.1.1", "10.1.1.1"])
    assert first["36.1.1.1"] == Verdict(True, 80, ("abuseipdb", "fixture"))
    assert first["73.1.1.1"] == Verdict(False, 0, ("abuseipdb",))
    assert "10.1.1.1" not in first
    service.verdicts(["36.1.1.1", "73.1.1.1"])
    assert len(http.calls) == 2


def test_service_refreshes_feeds_and_reloads_dictionary() -> None:
    store = MemoryIntelStore()
    service = ThreatIntelService(store, feeds=[FixtureProvider()])
    counts = service.refresh_feeds()
    assert counts["fixture"] == len(store.saved) > 0
    assert store.reloads == 1


WEIGHTS = RiskWeights()


@pytest.mark.parametrize(
    ("inputs", "expected"),
    [
        (RiskInputs(level="informational"), 0),
        (RiskInputs(level="low"), 10),
        (RiskInputs(level="medium"), 20),
        (RiskInputs(level="high"), 30),
        (RiskInputs(level="critical"), 40),
        (RiskInputs(level="medium", is_known_malicious=True), 40),
        (RiskInputs(level="medium", abuse_score=50), 30),
        (RiskInputs(level="high", foreign_country=True), 45),
        (RiskInputs(level="high", successful_login=True), 45),
        (RiskInputs(level="high", recent_alerts=5), 40),
        (RiskInputs(level="high", recent_alerts=50), 40),
        (
            RiskInputs(
                level="critical",
                is_known_malicious=True,
                foreign_country=True,
                successful_login=True,
                recent_alerts=5,
            ),
            100,
        ),
        (RiskInputs(level="unknown"), 0),
        (RiskInputs(level="medium", abuse_score=None), 20),
        (RiskInputs(level="high", foreign_country=True), 45),
        (
            RiskInputs(
                level="critical",
                is_known_malicious=True,
                foreign_country=True,
                successful_login=True,
                recent_alerts=2,
            ),
            94,
        ),
    ],
)
def test_risk_score_table(inputs: RiskInputs, expected: int) -> None:
    assert score(inputs, WEIGHTS).value == expected


def test_risk_weights_are_configurable(tmp_path: Path) -> None:
    config = tmp_path / "weights.yml"
    config.write_text(
        "weights: {level: 10, threat_intel: 90, foreign_country: 0, successful_login: 0, "
        "recurrence: 0}\n",
        encoding="utf-8",
    )
    weights = load_weights(config)
    assert score(RiskInputs(level="low", is_known_malicious=True), weights).value == 92
    assert load_weights().total == 100


BASE_ALERT = Alert(
    alert_id="a1",
    rule_id="r1",
    rule_name="rule",
    rule_title="Rule",
    rule_type="single",
    level="high",
    mitre_tactics=("credential-access",),
    mitre_techniques=("T1110",),
    entity_type="ip",
    entity="36.100.2.3",
    first_seen=NOW,
    last_seen=NOW,
    detected_at=NOW,
    event_ids={"e1": None},
    source_ip="36.100.2.3",
)


def make_alert(**overrides: Any) -> Alert:
    return replace(BASE_ALERT, **overrides)


def test_enricher_adds_location_intel_and_risk() -> None:
    intel = MemoryIntelStore({"36.100.2.3": Verdict(True, 92, ("fixture",))})
    enricher = AlertEnricher(
        GEO,
        intel,
        StaticBaselineLookup(organization={"TR"}),
        WEIGHTS,
        lambda kind, entity, since: 3,
    )
    [(_, context)] = enricher.enrich([make_alert()])
    assert (context.country_code, context.city, context.asn) == ("CN", "Shanghai", 4134)
    assert context.is_known_malicious
    assert context.risk.factors["foreign_country"] == 1.0
    assert context.risk.factors["recurrence"] == pytest.approx(0.4)
    assert context.risk.value == 69


def test_enricher_uses_user_baseline_for_user_alerts() -> None:
    enricher = AlertEnricher(
        GEO,
        MemoryIntelStore(),
        StaticBaselineLookup({"ayse": {"TR"}}, organization={"TR", "DE"}),
        WEIGHTS,
        lambda kind, entity, since: 1,
    )
    user = {"entity_type": "user", "entity": "ayse", "user_name": "ayse"}
    alerts = [
        make_alert(alert_id="home", source_ip="78.160.1.1", **user),
        make_alert(alert_id="away", source_ip="79.192.1.1", has_success=True, **user),
        make_alert(alert_id="internal", source_ip="10.20.0.10", first_seen=NOW - timedelta(1)),
    ]
    contexts = {alert.alert_id: context for alert, context in enricher.enrich(alerts)}
    assert contexts["home"].risk.factors["foreign_country"] == 0.0
    assert contexts["away"].risk.factors["foreign_country"] == 1.0
    assert contexts["away"].risk.factors["successful_login"] == 1.0
    assert contexts["internal"].country_code is None
