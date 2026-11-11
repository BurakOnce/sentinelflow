import hashlib
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from simulator.events import LogEvent, Source


@dataclass(frozen=True, slots=True)
class AttackLabel:
    attack_id: str
    scenario: str
    technique_id: str
    stage: str
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True, slots=True)
class LogRecord:
    event: LogEvent
    label: AttackLabel | None = None

    @property
    def timestamp(self) -> datetime:
        return self.event.timestamp


class GroundTruthLabel(BaseModel):
    model_config = ConfigDict(frozen=True)

    attack_id: str
    scenario: str
    technique_id: str
    stage: str
    source: Source
    event_time: datetime
    window_start: datetime
    window_end: datetime
    src_ip: str
    user: str | None
    line_sha256: str


def line_digest(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def ground_truth(event: LogEvent, label: AttackLabel, line: str) -> GroundTruthLabel:
    return GroundTruthLabel(
        attack_id=label.attack_id,
        scenario=label.scenario,
        technique_id=label.technique_id,
        stage=label.stage,
        source=event.source,
        event_time=event.timestamp,
        window_start=label.window_start,
        window_end=label.window_end,
        src_ip=event.src_ip,
        user=event.user,
        line_sha256=line_digest(line),
    )
