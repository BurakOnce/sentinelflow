import os
from dataclasses import dataclass, field

RAW_TOPIC_PATTERN = r"raw\.(nginx|ssh|firewall|app)"
DLQ_TOPIC = "raw.dlq"
NORMALIZED_TOPIC = "events.normalized"
ALERTS_TOPIC = "alerts"


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True, slots=True)
class StreamingSettings:
    kafka_bootstrap_servers: str = field(
        default_factory=lambda: _env("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092")
    )
    s3_endpoint: str = field(default_factory=lambda: _env("S3_ENDPOINT", "http://localhost:9000"))
    s3_access_key: str = field(default_factory=lambda: _env("S3_ACCESS_KEY", "sentinel"))
    s3_secret_key: str = field(default_factory=lambda: _env("S3_SECRET_KEY", ""))
    lake_root: str = field(default_factory=lambda: _env("LAKE_ROOT", "s3a://"))
    checkpoint_root: str = field(
        default_factory=lambda: _env("CHECKPOINT_ROOT", "s3a://checkpoints")
    )
    trigger_interval: str = field(
        default_factory=lambda: _env("STREAMING_TRIGGER_INTERVAL", "10 seconds")
    )
    max_offsets_per_trigger: int = field(
        default_factory=lambda: int(_env("STREAMING_MAX_OFFSETS_PER_TRIGGER", "200000"))
    )
    sink_retention: str = field(default_factory=lambda: _env("FILE_SINK_RETENTION", "30d"))
    starting_offsets: str = field(
        default_factory=lambda: _env("STREAMING_STARTING_OFFSETS", "earliest")
    )

    def lake_path(self, bucket: str, dataset: str) -> str:
        return f"{self.lake_root}{bucket}/{dataset}"

    def checkpoint(self, job: str, query: str) -> str:
        return f"{self.checkpoint_root.rstrip('/')}/{job}/{query}"
