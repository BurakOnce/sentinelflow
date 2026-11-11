from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from simulator.scenarios import SCENARIOS
from simulator.simulation import (
    AttackRequest,
    RealtimePacer,
    SimulationPlan,
    emit,
    parse_duration,
    simulate,
)
from simulator.sinks import FileSink, KafkaSink, Sink

app = typer.Typer(no_args_is_help=True, add_completion=False, help="SentinelFlow log simulator")


class TimeMode(StrEnum):
    BACKFILL = "backfill"
    REALTIME = "realtime"


class OutputMode(StrEnum):
    FILE = "file"
    KAFKA = "kafka"


def _parse_start(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _attack_requests(specs: list[str]) -> tuple[AttackRequest, ...]:
    try:
        return tuple(request for spec in specs for request in AttackRequest.parse(spec))
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--attack") from error


@app.command()
def run(
    mode: Annotated[TimeMode, typer.Option(help="Emit paced in real time or backfill history")] = (
        TimeMode.BACKFILL
    ),
    duration: Annotated[str, typer.Option(help="Simulated time span, e.g. 30m, 6h, 1d")] = "1h",
    start: Annotated[
        str | None, typer.Option(help="Backfill start in ISO 8601, defaults to now minus duration")
    ] = None,
    speed: Annotated[float, typer.Option(min=0.01, help="Real time speed multiplier")] = 1.0,
    seed: Annotated[int, typer.Option(help="Seed for reproducible output")] = 42,
    users: Annotated[int, typer.Option(min=10, help="Size of the simulated workforce")] = 200,
    attack: Annotated[
        list[str] | None,
        typer.Option("--attack", "-a", help="Scenario as name[:intensity], or all"),
    ] = None,
    attack_repeat: Annotated[int, typer.Option(min=1, help="Instances per scenario")] = 1,
    baseline: Annotated[bool, typer.Option(help="Include normal user activity")] = True,
    output: Annotated[OutputMode, typer.Option(help="Write files or produce to Kafka")] = (
        OutputMode.FILE
    ),
    output_dir: Annotated[Path, typer.Option(help="Root directory for file output")] = Path("data"),
    bootstrap_servers: Annotated[str, typer.Option(help="Kafka bootstrap servers")] = (
        "localhost:19092"
    ),
) -> None:
    try:
        span = parse_duration(duration)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--duration") from error
    if mode is TimeMode.REALTIME and start is not None:
        raise typer.BadParameter("realtime mode always starts now", param_hint="--start")
    now = datetime.now(UTC)
    if start is not None:
        begin = _parse_start(start)
    elif mode is TimeMode.REALTIME:
        begin = now
    else:
        begin = (now - span).replace(second=0, microsecond=0)
    plan = SimulationPlan(
        start=begin,
        end=begin + span,
        seed=seed,
        users=users,
        attacks=_attack_requests(attack or []),
        attack_repeat=attack_repeat,
        baseline=baseline,
    )
    pacer = RealtimePacer(begin, speed) if mode is TimeMode.REALTIME else None
    sink: Sink = (
        FileSink(output_dir) if output is OutputMode.FILE else KafkaSink.connect(bootstrap_servers)
    )
    typer.echo(f"simulating {plan.start.isoformat()} -> {plan.end.isoformat()} ({mode})")
    try:
        stats = emit(simulate(plan), sink, pacer)
    except KeyboardInterrupt:
        typer.echo("interrupted")
        raise typer.Exit(130) from None
    finally:
        sink.close()
    for source, count in sorted(stats.lines.items()):
        typer.echo(f"{source:<10}{count:>10}")
    typer.echo(f"{'labels':<10}{stats.labels:>10}")


@app.command()
def scenarios() -> None:
    for scenario in SCENARIOS.values():
        techniques = ", ".join(scenario.techniques)
        typer.echo(f"{scenario.name:<22}{techniques:<24}{scenario.description}")


if __name__ == "__main__":
    app()
