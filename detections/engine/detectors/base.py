from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol

from detections.engine.hits import Hit
from detections.engine.model import DetectorRule
from enrichment.geo import GeoLookup

Event = Mapping[str, Any]


class StateStore(Protocol):
    def get(self, detector: str, key: str) -> dict[str, Any] | None: ...

    def put(self, detector: str, key: str, value: dict[str, Any]) -> None: ...


class MemoryStateStore:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], dict[str, Any]] = {}

    def get(self, detector: str, key: str) -> dict[str, Any] | None:
        return self.values.get((detector, key))

    def put(self, detector: str, key: str, value: dict[str, Any]) -> None:
        self.values[(detector, key)] = value


class Detector(Protocol):
    def __call__(
        self, rule: DetectorRule, events: Sequence[Event], state: StateStore, geo: GeoLookup
    ) -> list[Hit]: ...


DETECTORS: dict[str, Detector] = {}


def register(name: str) -> Callable[[Detector], Detector]:
    def decorate(detector: Detector) -> Detector:
        DETECTORS[name] = detector
        return detector

    return decorate
