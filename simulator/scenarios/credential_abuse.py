from datetime import datetime
from random import Random

from simulator.activity import https_connection, portal_login, seconds
from simulator.events import AuthResult, FailureReason, MfaMethod
from simulator.geo import COUNTRIES, HOSTILE_COUNTRIES
from simulator.infrastructure import (
    DESKTOP_USER_AGENTS,
    MOBILE_USER_AGENTS,
    NONEXISTENT_ACCOUNTS,
    SCRIPT_USER_AGENTS,
)
from simulator.population import User
from simulator.scenarios.base import AttackStep, ScenarioContext, scaled, steps

PASSWORD_SPRAYING = "T1110.003"
CREDENTIAL_STUFFING = "T1110.004"
VALID_ACCOUNTS = "T1078"
LEAKED_FIRST_NAMES = ("john", "maria", "alex", "sarah", "mike", "anna", "david", "elena", "chris")
LEAKED_LAST_NAMES = ("smith", "garcia", "brown", "miller", "wilson", "moore", "lee", "clark")
LEAKED_DOMAINS = ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "mail.ru", "aol.com")


def _login_outcome(
    rng: Random, user: User | None, success_rate: float
) -> tuple[AuthResult, FailureReason | None, MfaMethod]:
    if user is None:
        return AuthResult.FAILURE, FailureReason.UNKNOWN_USER, MfaMethod.NONE
    if rng.random() >= success_rate:
        return AuthResult.FAILURE, FailureReason.INVALID_PASSWORD, user.mfa
    if user.mfa is MfaMethod.NONE:
        return AuthResult.SUCCESS, None, user.mfa
    return AuthResult.FAILURE, FailureReason.MFA_FAILED, user.mfa


def _leaked_email(rng: Random) -> str:
    separator = rng.choice((".", "_", ""))
    number = rng.choice(("", str(rng.randint(1, 99)), str(rng.randint(1970, 2005))))
    name = f"{rng.choice(LEAKED_FIRST_NAMES)}{separator}{rng.choice(LEAKED_LAST_NAMES)}{number}"
    return f"{name}@{rng.choice(LEAKED_DOMAINS)}"


def password_spraying(
    context: ScenarioContext, rng: Random, start: datetime, intensity: float
) -> list[AttackStep]:
    country = COUNTRIES[rng.choice(HOSTILE_COUNTRIES)]
    attacker_ips = [country.random_ip(rng) for _ in range(rng.randint(3, 5))]
    agent = rng.choice(SCRIPT_USER_AGENTS)
    targets: list[tuple[str, User | None]] = [
        (user.username, user)
        for user in rng.sample(list(context.users), min(len(context.users), scaled(40, intensity)))
    ]
    targets += [(name, None) for name in rng.sample(NONEXISTENT_ACCOUNTS, 3)]
    result: list[AttackStep] = []
    now = start
    for ip in attacker_ips:
        result += steps([https_connection(rng, now, ip)], PASSWORD_SPRAYING, "connection")
    for _round in range(rng.randint(1, 2)):
        rng.shuffle(targets)
        for index, (username, user) in enumerate(targets):
            ip = attacker_ips[index % len(attacker_ips)]
            outcome = _login_outcome(rng, user, success_rate=0.02)
            events = portal_login(rng, now, ip, username, agent, *outcome)
            technique = VALID_ACCOUNTS if outcome[0] is AuthResult.SUCCESS else PASSWORD_SPRAYING
            result += steps(events, technique, "attempt")
            now += seconds(rng.uniform(2, 12))
        now += seconds(rng.uniform(600, 1200))
    return result


def credential_stuffing(
    context: ScenarioContext, rng: Random, start: datetime, intensity: float
) -> list[AttackStep]:
    countries = list(COUNTRIES.values())
    proxy_ips = [rng.choice(countries).random_ip(rng) for _ in range(scaled(60, intensity, 10))]
    agents = DESKTOP_USER_AGENTS + MOBILE_USER_AGENTS
    users = list(context.users)
    result: list[AttackStep] = []
    connected: set[str] = set()
    now = start
    for _ in range(scaled(300, intensity, minimum=30)):
        user = rng.choice(users) if rng.random() < 0.3 else None
        username = user.username if user else _leaked_email(rng)
        ip = rng.choice(proxy_ips)
        if ip not in connected:
            connected.add(ip)
            result += steps([https_connection(rng, now, ip)], CREDENTIAL_STUFFING, "connection")
        outcome = _login_outcome(rng, user, success_rate=0.05)
        events = portal_login(rng, now, ip, username, rng.choice(agents), *outcome)
        technique = VALID_ACCOUNTS if outcome[0] is AuthResult.SUCCESS else CREDENTIAL_STUFFING
        result += steps(events, technique, "attempt")
        now += seconds(rng.expovariate(1 / 3))
    return result
