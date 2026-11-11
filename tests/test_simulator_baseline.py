from collections import Counter
from datetime import timedelta

from conftest import SIMULATION_START

from simulator.baseline import BaselineGenerator
from simulator.events import AppAuthEvent, AuthResult, FailureReason, LogEvent
from simulator.geo import COUNTRIES
from simulator.population import User, build_population
from simulator.records import line_digest
from simulator.simulation import AttackRequest, SimulationPlan, simulate


def baseline_day(population: tuple[User, ...]) -> list[LogEvent]:
    generator = BaselineGenerator(population, seed=11)
    return list(generator.events(SIMULATION_START, SIMULATION_START + timedelta(days=1)))


def test_population_is_mostly_turkish_with_unique_accounts(population: tuple[User, ...]) -> None:
    countries = Counter(user.city.country_code for user in population)
    assert len(population) == 200
    assert countries["TR"] / len(population) > 0.7
    assert len({user.username for user in population}) == len(population)
    assert all(user.username.isascii() for user in population)


def test_user_addresses_come_from_their_home_country(population: tuple[User, ...]) -> None:
    for user in population:
        country = COUNTRIES[user.city.country_code]
        assert country.locate(user.home_ip)
        assert country.locate(user.mobile_ip)


def test_baseline_is_time_ordered_and_quiet_at_night(population: tuple[User, ...]) -> None:
    events = baseline_day(population)
    logins = [event for event in events if isinstance(event, AppAuthEvent)]
    by_turkish_hour = Counter((event.timestamp.hour + 3) % 24 for event in logins)
    night = sum(by_turkish_hour[hour] for hour in range(0, 6))
    working = sum(by_turkish_hour[hour] for hour in range(10, 16))
    assert [event.timestamp for event in events] == sorted(event.timestamp for event in events)
    assert working > 10 * max(night, 1)


def test_baseline_contains_occasional_password_typos(population: tuple[User, ...]) -> None:
    logins = [event for event in baseline_day(population) if isinstance(event, AppAuthEvent)]
    typos = [event for event in logins if event.reason is FailureReason.INVALID_PASSWORD]
    successes = [event for event in logins if event.result is AuthResult.SUCCESS]
    assert typos
    assert len(typos) < 0.1 * len(successes)


def test_weekend_traffic_is_lower_than_weekday(population: tuple[User, ...]) -> None:
    generator = BaselineGenerator(population, seed=11)
    saturday = SIMULATION_START + timedelta(days=5)
    weekday_logins = sum(
        isinstance(event, AppAuthEvent)
        for event in generator.events(SIMULATION_START, SIMULATION_START + timedelta(days=1))
    )
    weekend_logins = sum(
        isinstance(event, AppAuthEvent)
        for event in generator.events(saturday, saturday + timedelta(days=1))
    )
    assert weekend_logins < weekday_logins / 3


def rendered(seed: int) -> list[str]:
    plan = SimulationPlan(
        start=SIMULATION_START,
        end=SIMULATION_START + timedelta(hours=4),
        seed=seed,
        users=50,
        attacks=tuple(AttackRequest.parse("all")),
    )
    return [record.event.render() for record in simulate(plan)]


def test_same_seed_reproduces_identical_output() -> None:
    assert rendered(5) == rendered(5)


def test_different_seeds_produce_different_output() -> None:
    assert rendered(5) != rendered(6)


def test_population_is_reproducible_from_seed() -> None:
    assert build_population(3, 20) == build_population(3, 20)


def test_log_lines_carry_no_ground_truth_markers() -> None:
    plan = SimulationPlan(
        start=SIMULATION_START,
        end=SIMULATION_START + timedelta(hours=4),
        users=50,
        attacks=tuple(AttackRequest.parse("all")),
    )
    records = list(simulate(plan))
    lines = "\n".join(record.event.render() for record in records).lower()
    labelled = [record for record in records if record.label is not None]
    assert labelled
    for marker in ("attack_id", "scenario", "technique", "t1110", "bruteforce", "ground_truth"):
        assert marker not in lines
    digests = {line_digest(record.event.render()) for record in labelled}
    assert len(digests) > 0.95 * len(labelled)
