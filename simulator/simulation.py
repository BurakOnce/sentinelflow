import heapq
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from random import Random

from simulator.baseline import BaselineGenerator
from simulator.population import build_population
from simulator.records import AttackLabel, LogRecord
from simulator.scenarios import SCENARIOS, Scenario, ScenarioContext
from simulator.sinks import Sink

DURATION_PATTERN = re.compile(r"(\d+)([smhd])")
DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_duration(value: str) -> timedelta:
    parts = DURATION_PATTERN.findall(value.strip().lower())
    if not parts or "".join(amount + unit for amount, unit in parts) != value.strip().lower():
        raise ValueError(f"invalid duration {value!r}, expected values like 30m, 2h or 1d12h")
    return sum(
        (timedelta(**{DURATION_UNITS[unit]: int(amount)}) for amount, unit in parts), timedelta()
    )


@dataclass(frozen=True, slots=True)
class AttackRequest:
    scenario: str
    intensity: float = 1.0

    @classmethod
    def parse(cls, spec: str) -> list["AttackRequest"]:
        name, _, intensity = spec.partition(":")
        factor = float(intensity) if intensity else 1.0
        if factor <= 0:
            raise ValueError(f"intensity must be positive in {spec!r}")
        if name == "all":
            return [cls(scenario, factor) for scenario in SCENARIOS]
        if name not in SCENARIOS:
            raise ValueError(f"unknown scenario {name!r}, choose from {', '.join(SCENARIOS)}")
        return [cls(name, factor)]


@dataclass(frozen=True, slots=True)
class SimulationPlan:
    start: datetime
    end: datetime
    seed: int = 42
    users: int = 200
    attacks: tuple[AttackRequest, ...] = ()
    attack_repeat: int = 1
    baseline: bool = True


def materialize_attack(
    scenario: Scenario,
    context: ScenarioContext,
    rng: Random,
    attack_id: str,
    start: datetime,
    end: datetime,
    intensity: float,
) -> list[LogRecord]:
    attack_steps = sorted(
        scenario.generate(context, rng, start, intensity), key=lambda step: step.event.timestamp
    )
    if not attack_steps:
        return []
    first, last = attack_steps[0].event.timestamp, attack_steps[-1].event.timestamp
    slack = max((end - start - (last - first)).total_seconds(), 0.0)
    shift = start + timedelta(seconds=rng.uniform(0.0, slack)) - first
    records = [
        LogRecord(
            step.event.shifted(shift),
            AttackLabel(
                attack_id=attack_id,
                scenario=scenario.name,
                technique_id=step.technique_id,
                stage=step.stage,
                window_start=first + shift,
                window_end=last + shift,
            ),
        )
        for step in attack_steps
    ]
    return [record for record in records if record.timestamp < end]


def attack_records(plan: SimulationPlan, context: ScenarioContext) -> list[list[LogRecord]]:
    instances: Counter[str] = Counter()
    streams: list[list[LogRecord]] = []
    for request in plan.attacks:
        scenario = SCENARIOS[request.scenario]
        for _ in range(plan.attack_repeat):
            instances[scenario.name] += 1
            number = instances[scenario.name]
            rng = Random(f"{plan.seed}:attack:{scenario.name}:{number}")
            attack_id = f"{scenario.name}-{number:03d}"
            streams.append(
                materialize_attack(
                    scenario, context, rng, attack_id, plan.start, plan.end, request.intensity
                )
            )
    return streams


def simulate(plan: SimulationPlan) -> Iterator[LogRecord]:
    users = build_population(plan.seed, plan.users)
    streams: list[Iterable[LogRecord]] = [*attack_records(plan, ScenarioContext(users))]
    if plan.baseline:
        baseline = BaselineGenerator(users, plan.seed).events(plan.start, plan.end)
        streams.insert(0, (LogRecord(event) for event in baseline))
    return heapq.merge(*streams, key=lambda record: record.timestamp)


@dataclass(slots=True)
class RealtimePacer:
    simulation_start: datetime
    speed: float
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    _wall_start: float | None = field(default=None, init=False)

    def delay_until(self, timestamp: datetime) -> float:
        if self._wall_start is None:
            self._wall_start = self.monotonic()
        simulated = (timestamp - self.simulation_start).total_seconds() / self.speed
        return self._wall_start + simulated - self.monotonic()


@dataclass(slots=True)
class EmitStats:
    lines: Counter[str] = field(default_factory=Counter)
    labels: int = 0


def emit(records: Iterable[LogRecord], sink: Sink, pacer: RealtimePacer | None = None) -> EmitStats:
    stats = EmitStats()
    for record in records:
        if pacer is not None:
            delay = pacer.delay_until(record.timestamp)
            if delay > 0:
                sink.flush()
                pacer.sleep(delay)
        sink.write(record)
        stats.lines[record.event.source] += 1
        stats.labels += record.label is not None
    sink.flush()
    return stats
