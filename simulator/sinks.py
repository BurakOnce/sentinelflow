from pathlib import Path
from typing import IO, Any, Protocol, Self

from simulator.events import Source
from simulator.records import LogRecord, ground_truth

LOG_FILES: dict[Source, Path] = {
    Source.NGINX: Path("nginx/access.log"),
    Source.SSH: Path("ssh/auth.log"),
    Source.FIREWALL: Path("firewall/firewall.log"),
    Source.APP: Path("app/auth.log"),
}
LABELS_FILE = Path("labels/ground_truth.jsonl")
LABELS_TOPIC = "labels.ground_truth"


def raw_topic(source: Source) -> str:
    return f"raw.{source}"


class Sink(Protocol):
    def write(self, record: LogRecord) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class FileSink:
    def __init__(self, root: Path) -> None:
        self._root = root
        self._handles: dict[Path, IO[str]] = {}

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _handle(self, relative: Path) -> IO[str]:
        if relative not in self._handles:
            path = self._root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            self._handles[relative] = path.open("a", encoding="utf-8", newline="\n")
        return self._handles[relative]

    def write(self, record: LogRecord) -> None:
        line = record.event.render()
        self._handle(Path("logs") / LOG_FILES[record.event.source]).write(line + "\n")
        if record.label is not None:
            label = ground_truth(record.event, record.label, line)
            self._handle(LABELS_FILE).write(label.model_dump_json() + "\n")

    def flush(self) -> None:
        for handle in self._handles.values():
            handle.flush()

    def close(self) -> None:
        for handle in self._handles.values():
            handle.close()
        self._handles.clear()


class Producer(Protocol):
    def produce(self, topic: str, value: bytes, key: bytes | None = None) -> None: ...

    def poll(self, timeout: float) -> int: ...

    def flush(self, timeout: float) -> int: ...


class KafkaSink:
    def __init__(self, producer: Producer) -> None:
        self._producer = producer

    @classmethod
    def connect(cls, bootstrap_servers: str) -> "KafkaSink":
        from confluent_kafka import Producer as KafkaProducer

        config: dict[str, Any] = {
            "bootstrap.servers": bootstrap_servers,
            "linger.ms": 50,
            "compression.type": "lz4",
            "enable.idempotence": True,
        }
        producer: Producer = KafkaProducer(config)
        return cls(producer)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _produce(self, topic: str, value: str, key: str) -> None:
        while True:
            try:
                self._producer.produce(topic, value.encode("utf-8"), key.encode("utf-8"))
            except BufferError:
                self._producer.poll(0.5)
            else:
                self._producer.poll(0)
                return

    def write(self, record: LogRecord) -> None:
        line = record.event.render()
        self._produce(raw_topic(record.event.source), line, record.event.src_ip)
        if record.label is not None:
            label = ground_truth(record.event, record.label, line)
            self._produce(LABELS_TOPIC, label.model_dump_json(), label.attack_id)

    def flush(self) -> None:
        self._producer.flush(10.0)

    def close(self) -> None:
        self.flush()
