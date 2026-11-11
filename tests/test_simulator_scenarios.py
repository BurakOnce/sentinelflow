from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import timedelta
from urllib.parse import unquote

import pytest

from simulator.events import (
    AppAuthEvent,
    AuthResult,
    FirewallEvent,
    HttpRequest,
    LogEvent,
    SshEvent,
    SshEventKind,
)
from simulator.geo import country_of, distance_km
from simulator.population import User
from simulator.records import LogRecord
from simulator.scenarios import SCENARIOS

ScenarioRunner = Callable[..., list[LogRecord]]
FAILED_SSH = {SshEventKind.FAILED_PASSWORD, SshEventKind.FAILED_PASSWORD_INVALID_USER}


def events_of[T: LogEvent](records: list[LogRecord], kind: type[T]) -> list[T]:
    return [record.event for record in records if isinstance(record.event, kind)]


def test_ssh_bruteforce_is_one_source_hammering_one_account(run_scenario: ScenarioRunner) -> None:
    failures = [
        e for e in events_of(run_scenario("ssh_bruteforce"), SshEvent) if e.kind in FAILED_SSH
    ]
    assert len(failures) >= 100
    assert len({event.src_ip for event in failures}) == 1
    assert len({event.username for event in failures}) == 1
    span = failures[-1].timestamp - failures[0].timestamp
    assert span < timedelta(minutes=10)


def test_password_spraying_touches_many_accounts_few_times(run_scenario: ScenarioRunner) -> None:
    logins = events_of(run_scenario("password_spraying"), AppAuthEvent)
    attempts_per_user = Counter(event.username for event in logins)
    assert 3 <= len({event.src_ip for event in logins}) <= 5
    assert len(attempts_per_user) >= 30
    assert max(attempts_per_user.values()) <= 2


def test_credential_stuffing_is_distributed_with_low_success(run_scenario: ScenarioRunner) -> None:
    logins = events_of(run_scenario("credential_stuffing"), AppAuthEvent)
    successes = sum(event.result is AuthResult.SUCCESS for event in logins)
    assert len(logins) >= 300
    assert len({event.src_ip for event in logins}) >= 40
    assert len({event.username for event in logins}) >= 150
    assert len({event.user_agent for event in logins}) >= 5
    assert successes / len(logins) < 0.05


def test_brute_force_success_ends_with_login_from_same_source(
    run_scenario: ScenarioRunner,
) -> None:
    ssh = events_of(run_scenario("brute_force_success"), SshEvent)
    failures = [event for event in ssh if event.kind in FAILED_SSH]
    accepted = [event for event in ssh if event.kind is SshEventKind.ACCEPTED_PASSWORD]
    assert len(failures) >= 50
    assert len(accepted) == 1
    assert accepted[0].timestamp > max(event.timestamp for event in failures)
    assert {event.src_ip for event in ssh} == {accepted[0].src_ip}
    assert {event.username for event in ssh} == {accepted[0].username}


def test_port_scan_hits_many_ports_from_one_source_quickly(run_scenario: ScenarioRunner) -> None:
    packets = events_of(run_scenario("port_scan"), FirewallEvent)
    ports_by_source: defaultdict[str, set[int]] = defaultdict(set)
    for packet in packets:
        ports_by_source[packet.src_ip].add(packet.dst_port)
    assert len(ports_by_source) == 1
    assert len(next(iter(ports_by_source.values()))) >= 500
    assert packets[-1].timestamp - packets[0].timestamp < timedelta(minutes=2)


def test_web_attack_contains_injection_patterns_and_scanner_agents(
    run_scenario: ScenarioRunner,
) -> None:
    requests = events_of(run_scenario("web_attack"), HttpRequest)
    decoded = [unquote(request.path).lower() for request in requests]
    agents = " ".join(request.user_agent for request in requests)
    assert len({request.src_ip for request in requests}) == 1
    assert any("union" in path and "select" in path for path in decoded)
    assert any("' or '1'='1" in path for path in decoded)
    assert any("../" in path and "etc/passwd" in path for path in decoded)
    assert any("<script>" in path or "onerror=" in path for path in decoded)
    assert "sqlmap" in agents
    assert "Nikto" in agents


def test_impossible_travel_logins_are_too_far_apart_to_be_real(
    run_scenario: ScenarioRunner, population: tuple[User, ...]
) -> None:
    logins = [
        event
        for event in events_of(run_scenario("impossible_travel"), AppAuthEvent)
        if event.result is AuthResult.SUCCESS
    ]
    assert len(logins) == 2
    first, second = sorted(logins, key=lambda event: event.timestamp)
    assert first.username == second.username
    victim = next(user for user in population if user.username == first.username)
    remote_country = country_of(second.src_ip)
    assert remote_country is not None
    assert remote_country.code != victim.city.country_code
    hours = (second.timestamp - first.timestamp) / timedelta(hours=1)
    closest_km = min(distance_km(victim.city, city) for city in remote_country.cities)
    assert hours <= 1.5
    assert closest_km / hours > 1000


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_every_attack_record_is_labelled_with_scenario_metadata(
    run_scenario: ScenarioRunner, name: str
) -> None:
    records = run_scenario(name)
    assert records
    for record in records:
        assert record.label is not None
        assert record.label.scenario == name
        assert record.label.technique_id in SCENARIOS[name].techniques
        assert record.label.window_start <= record.timestamp <= record.label.window_end


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_intensity_scales_attack_volume(run_scenario: ScenarioRunner, name: str) -> None:
    assert len(run_scenario(name, intensity=3.0)) > len(run_scenario(name, intensity=0.5))
