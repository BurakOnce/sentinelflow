from datetime import datetime
from random import Random

from simulator.activity import https_connection, portal_login, seconds
from simulator.events import AuthResult
from simulator.geo import COUNTRIES, DISTANT_COUNTRIES, distance_km
from simulator.infrastructure import DESKTOP_USER_AGENTS
from simulator.scenarios.base import AttackStep, ScenarioContext, scaled, steps

VALID_ACCOUNTS = "T1078"
MIN_TRAVEL_DISTANCE_KM = 3000.0


def impossible_travel(
    context: ScenarioContext, rng: Random, start: datetime, intensity: float
) -> list[AttackStep]:
    victims = rng.sample(list(context.users), min(len(context.users), scaled(1, intensity)))
    result: list[AttackStep] = []
    for victim in victims:
        anchor_time = start + seconds(rng.uniform(0, 1800))
        result += steps(
            [
                https_connection(rng, anchor_time, victim.home_ip),
                *portal_login(
                    rng,
                    anchor_time,
                    victim.home_ip,
                    victim.username,
                    victim.desktop_agent,
                    AuthResult.SUCCESS,
                    None,
                    victim.mfa,
                ),
            ],
            VALID_ACCOUNTS,
            "anchor_login",
        )
        candidates = [
            city
            for code in DISTANT_COUNTRIES
            for city in COUNTRIES[code].cities
            if code != victim.city.country_code
            and distance_km(victim.city, city) >= MIN_TRAVEL_DISTANCE_KM
        ]
        remote_city = rng.choice(candidates)
        remote_ip = COUNTRIES[remote_city.country_code].random_ip(rng)
        remote_time = anchor_time + seconds(rng.uniform(10 * 60, 90 * 60))
        agent = rng.choice(
            [agent for agent in DESKTOP_USER_AGENTS if agent != victim.desktop_agent]
        )
        result += steps(
            [
                https_connection(rng, remote_time, remote_ip),
                *portal_login(
                    rng,
                    remote_time,
                    remote_ip,
                    victim.username,
                    agent,
                    AuthResult.SUCCESS,
                    None,
                    victim.mfa,
                ),
            ],
            VALID_ACCOUNTS,
            "remote_login",
        )
    return result
