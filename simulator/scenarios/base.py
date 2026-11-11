from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from random import Random

from simulator.events import LogEvent
from simulator.population import User


@dataclass(frozen=True, slots=True)
class AttackStep:
    event: LogEvent
    technique_id: str
    stage: str


@dataclass(frozen=True, slots=True)
class ScenarioContext:
    users: Sequence[User]

    def ssh_users(self) -> list[User]:
        return [user for user in self.users if user.ssh_access] or list(self.users)


ScenarioFunction = Callable[[ScenarioContext, Random, datetime, float], list[AttackStep]]


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    description: str
    techniques: tuple[str, ...]
    generate: ScenarioFunction


def scaled(base: int, intensity: float, minimum: int = 1) -> int:
    return max(minimum, round(base * intensity))


def steps(events: Sequence[LogEvent], technique_id: str, stage: str) -> list[AttackStep]:
    return [AttackStep(event, technique_id, stage) for event in events]
