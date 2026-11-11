from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from detections.engine.loader import RuleSet
from detections.engine.runner import evaluate
from enrichment.geo import GeoLookup
from simulator.events import iso_millis, nginx_time, rfc3339
from streaming.parsing.python_parser import parse_line

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
TIME_FORMATS: dict[str, Callable[[datetime], str]] = {
    "nginx": nginx_time,
    "ssh": rfc3339,
    "firewall": rfc3339,
    "app": iso_millis,
}


class LineSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["nginx", "ssh", "firewall", "app"]
    raw: str
    at: float = 0.0
    repeat: int = Field(default=1, ge=1, le=5000)
    every: float = 1.0


class CaseSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    expect: Literal["alert", "no_alert"]
    count: int | None = None
    lines: list[LineSpec] = Field(min_length=1)


class FixtureFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: str
    start: datetime = datetime(2026, 9, 28, 9, tzinfo=UTC)
    cases: list[CaseSpec] = Field(min_length=1)


@dataclass(frozen=True, slots=True)
class CaseResult:
    rule: str
    case: str
    expected: str
    alerts: int
    passed: bool


def render(case: CaseSpec, start: datetime) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for spec in case.lines:
        for index in range(spec.repeat):
            moment = start + timedelta(seconds=spec.at + index * spec.every)
            lines.append(
                (spec.source, spec.raw.format(ts=TIME_FORMATS[spec.source](moment), n=index))
            )
    return lines


def events_for(case: CaseSpec, start: datetime) -> list[dict[str, Any]]:
    return [parse_line(source, raw, start).as_dict() for source, raw in render(case, start)]


def load_fixture(path: Path) -> FixtureFile:
    return FixtureFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def run_fixtures(
    rules: RuleSet, geo: GeoLookup, directory: Path = FIXTURES_DIR
) -> list[CaseResult]:
    results = []
    for path in sorted(directory.glob("*.yml")):
        fixture = load_fixture(path)
        for case in fixture.cases:
            alerts = [
                alert
                for alert in evaluate(rules, events_for(case, fixture.start), geo)
                if alert.rule_name == fixture.rule
            ]
            if case.expect == "no_alert":
                passed = not alerts
            else:
                passed = bool(alerts) and (case.count is None or len(alerts) == case.count)
            results.append(CaseResult(fixture.rule, case.name, case.expect, len(alerts), passed))
    return results


def missing_positive_fixtures(rules: RuleSet, results: list[CaseResult]) -> list[str]:
    positives = Counter(result.rule for result in results if result.expected == "alert")
    return sorted(rule.meta.name for rule in rules.alerting if positives[rule.meta.name] == 0)
