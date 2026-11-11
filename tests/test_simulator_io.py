import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from simulator.cli import app
from simulator.events import Source
from simulator.records import line_digest
from simulator.simulation import (
    AttackRequest,
    RealtimePacer,
    SimulationPlan,
    emit,
    parse_duration,
    simulate,
)
from simulator.sinks import LABELS_TOPIC, LOG_FILES, FileSink, KafkaSink, raw_topic

ROOT = Path(__file__).resolve().parent.parent
START = datetime(2026, 9, 28, 8, tzinfo=UTC)


def small_plan(duration: timedelta = timedelta(hours=1)) -> SimulationPlan:
    return SimulationPlan(
        start=START,
        end=START + duration,
        users=20,
        attacks=tuple(AttackRequest.parse("ssh_bruteforce:0.2")),
    )


class FakeProducer:
    def __init__(self, fail_first: int = 0) -> None:
        self.messages: list[tuple[str, bytes, bytes | None]] = []
        self.polls = 0
        self._fail_first = fail_first

    def produce(self, topic: str, value: bytes, key: bytes | None = None) -> None:
        if self._fail_first:
            self._fail_first -= 1
            raise BufferError
        self.messages.append((topic, value, key))

    def poll(self, timeout: float) -> int:
        self.polls += 1
        return 0

    def flush(self, timeout: float) -> int:
        return 0


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30m", timedelta(minutes=30)),
        ("1d12h", timedelta(hours=36)),
        ("45s", timedelta(seconds=45)),
    ],
)
def test_parse_duration(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "10", "5x", "1h 2"])
def test_parse_duration_rejects_garbage(text: str) -> None:
    with pytest.raises(ValueError, match="invalid duration"):
        parse_duration(text)


def test_attack_request_parsing() -> None:
    assert AttackRequest.parse("port_scan:2.5") == [AttackRequest("port_scan", 2.5)]
    assert len(AttackRequest.parse("all")) == 7
    with pytest.raises(ValueError, match="unknown scenario"):
        AttackRequest.parse("ddos")


def test_file_sink_writes_logs_and_matching_labels(tmp_path: Path) -> None:
    with FileSink(tmp_path) as sink:
        stats = emit(simulate(small_plan()), sink)
    ssh_lines = (tmp_path / "logs/ssh/auth.log").read_text(encoding="utf-8").splitlines()
    labels = [
        json.loads(line)
        for line in (tmp_path / "labels/ground_truth.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    digests = {line_digest(line) for line in ssh_lines}
    assert stats.labels == len(labels) > 0
    assert {label["scenario"] for label in labels} == {"ssh_bruteforce"}
    assert all(label["line_sha256"] in digests for label in labels if label["source"] == "ssh")
    assert b"\r\n" not in (tmp_path / "logs/nginx/access.log").read_bytes()


def test_kafka_sink_routes_by_source_and_retries_full_buffer() -> None:
    producer = FakeProducer(fail_first=2)
    emit(simulate(small_plan()), KafkaSink(producer))
    topics = {topic for topic, _, _ in producer.messages}
    assert topics <= {raw_topic(source) for source in Source} | {LABELS_TOPIC}
    assert LABELS_TOPIC in topics
    assert producer.polls >= 2


def test_realtime_pacer_spaces_events_by_speed() -> None:
    clock = FakeClock()
    pacer = RealtimePacer(START, speed=10.0, monotonic=clock.monotonic, sleep=clock.sleep)
    assert pacer.delay_until(START) == 0
    assert pacer.delay_until(START + timedelta(seconds=50)) == pytest.approx(5.0)


def test_emit_sleeps_in_realtime_mode(tmp_path: Path) -> None:
    clock = FakeClock()
    plan = small_plan(timedelta(minutes=10))
    pacer = RealtimePacer(START, speed=60.0, monotonic=clock.monotonic, sleep=clock.sleep)
    with FileSink(tmp_path) as sink:
        emit(simulate(plan), sink, pacer)
    assert clock.sleeps
    assert sum(clock.sleeps) == pytest.approx(10.0, abs=0.5)


def test_cli_backfill_writes_all_sources(tmp_path: Path) -> None:
    arguments = "run --start 2026-09-28T08:00:00Z --duration 2h --users 30 --attack all"
    result = CliRunner().invoke(app, [*arguments.split(), "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    for relative in LOG_FILES.values():
        assert (tmp_path / "logs" / relative).stat().st_size > 0
    assert (tmp_path / "labels/ground_truth.jsonl").stat().st_size > 0


def test_cli_rejects_unknown_scenario() -> None:
    result = CliRunner().invoke(app, ["run", "--attack", "ddos"])
    assert result.exit_code != 0


def test_vector_routes_every_simulator_source_to_its_topic() -> None:
    config = yaml.safe_load((ROOT / "ingestion/vector/vector.yaml").read_text(encoding="utf-8"))
    includes = " ".join(config["sources"]["raw_logs"]["include"])
    remap = config["transforms"]["tag_log_type"]["source"]
    assert config["sinks"]["redpanda_raw"]["topic"] == "raw.{{ log_type }}"
    assert config["sinks"]["redpanda_labels"]["topic"] == LABELS_TOPIC
    for source in Source:
        assert f"/data/logs/{source}/" in includes
        assert source.value in remap
        assert raw_topic(source) == f"raw.{source}"
