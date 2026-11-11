import importlib
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = [
    "simulator",
    "streaming",
    "detections",
    "detections.engine",
    "enrichment",
    "orchestration.definitions",
]
ONE_SHOT_SERVICES = {"minio-init", "redpanda-topics", "clickhouse-init", "simulator"}
PROFILES = {"core", "streaming", "batch", "observability", "tools"}


@pytest.fixture(scope="module")
def compose_services() -> dict[str, dict[str, Any]]:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services: dict[str, dict[str, Any]] = compose["services"]
    return services


@pytest.mark.parametrize("package", PACKAGES)
def test_package_is_importable(package: str) -> None:
    importlib.import_module(package)


def test_every_service_belongs_to_a_known_profile(
    compose_services: dict[str, dict[str, Any]],
) -> None:
    for name, service in compose_services.items():
        assert set(service.get("profiles", [])) & PROFILES, name


def test_long_running_services_define_healthchecks(
    compose_services: dict[str, dict[str, Any]],
) -> None:
    missing = [
        name
        for name, service in compose_services.items()
        if name not in ONE_SHOT_SERVICES and "healthcheck" not in service
    ]
    assert missing == []


def test_env_example_covers_compose_variables() -> None:
    compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    env_lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    defined = {line.split("=", 1)[0] for line in env_lines if "=" in line}
    referenced = {token.split("}", 1)[0] for token in compose_text.split("${")[1:]}
    assert referenced - defined == set()


def test_minio_init_creates_medallion_buckets(
    compose_services: dict[str, dict[str, Any]],
) -> None:
    script = "\n".join(compose_services["minio-init"]["command"])
    assert "bronze silver gold" in script
