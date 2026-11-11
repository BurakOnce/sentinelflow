from datetime import datetime
from random import Random

from simulator.activity import ephemeral_port, seconds, ssh_connection, ssh_password_attempt
from simulator.geo import COUNTRIES, HOSTILE_COUNTRIES
from simulator.infrastructure import EXISTING_SYSTEM_ACCOUNTS, NONEXISTENT_ACCOUNTS
from simulator.scenarios.base import AttackStep, ScenarioContext, scaled, steps

PASSWORD_GUESSING = "T1110.001"
VALID_ACCOUNTS = "T1078"
ATTEMPTS_PER_CONNECTION = 6


def _hostile_ip(rng: Random) -> str:
    return COUNTRIES[rng.choice(HOSTILE_COUNTRIES)].random_ip(rng)


def _guessing_run(
    rng: Random,
    start: datetime,
    attacker_ip: str,
    username: str,
    known_user: bool,
    attempts: int,
) -> list[AttackStep]:
    result: list[AttackStep] = []
    now = start
    pid = port = 0
    for attempt in range(attempts):
        if attempt % ATTEMPTS_PER_CONNECTION == 0:
            pid, port = rng.randint(20_000, 65_000), ephemeral_port(rng)
            result += steps(
                [ssh_connection(rng, now, attacker_ip)], PASSWORD_GUESSING, "connection"
            )
            now += seconds(rng.uniform(0.2, 0.5))
        events = ssh_password_attempt(rng, now, attacker_ip, username, known_user, False, pid, port)
        result += steps(events, PASSWORD_GUESSING, "attempt")
        now += seconds(rng.uniform(0.4, 1.2))
    return result


def ssh_bruteforce(
    context: ScenarioContext, rng: Random, start: datetime, intensity: float
) -> list[AttackStep]:
    roll = rng.random()
    if roll < 0.4:
        username, known_user = rng.choice(EXISTING_SYSTEM_ACCOUNTS), True
    elif roll < 0.7:
        username, known_user = rng.choice(NONEXISTENT_ACCOUNTS), False
    else:
        username, known_user = rng.choice(context.ssh_users()).username, True
    attempts = scaled(150, intensity, minimum=20)
    return _guessing_run(rng, start, _hostile_ip(rng), username, known_user, attempts)


def brute_force_success(
    context: ScenarioContext, rng: Random, start: datetime, intensity: float
) -> list[AttackStep]:
    victim = rng.choice(context.ssh_users())
    attacker_ip = _hostile_ip(rng)
    failures = scaled(60, intensity, minimum=10)
    result = _guessing_run(rng, start, attacker_ip, victim.username, True, failures)
    now = max(step.event.timestamp for step in result) + seconds(rng.uniform(0.3, 1.0))
    result += steps([ssh_connection(rng, now, attacker_ip)], PASSWORD_GUESSING, "connection")
    success = ssh_password_attempt(
        rng,
        now + seconds(rng.uniform(0.2, 0.5)),
        attacker_ip,
        victim.username,
        True,
        True,
        rng.randint(20_000, 65_000),
        ephemeral_port(rng),
        victim.uid,
    )
    return result + steps(success, VALID_ACCOUNTS, "compromise")
