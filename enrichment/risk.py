from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_WEIGHTS_FILE = Path(__file__).parent / "risk_weights.yml"
DEFAULT_LEVEL_FACTORS = {
    "informational": 0.0,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}


@dataclass(frozen=True, slots=True)
class RiskWeights:
    level: float = 40.0
    threat_intel: float = 20.0
    foreign_country: float = 15.0
    successful_login: float = 15.0
    recurrence: float = 10.0
    recurrence_saturation: int = 5
    level_factors: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_LEVEL_FACTORS))

    @property
    def total(self) -> float:
        return (
            self.level
            + self.threat_intel
            + self.foreign_country
            + self.successful_login
            + self.recurrence
        )


@dataclass(frozen=True, slots=True)
class RiskInputs:
    level: str
    is_known_malicious: bool = False
    abuse_score: int | None = None
    foreign_country: bool = False
    successful_login: bool = False
    recent_alerts: int = 0


@dataclass(frozen=True, slots=True)
class RiskScore:
    value: int
    factors: dict[str, float]


def load_weights(path: Path = DEFAULT_WEIGHTS_FILE) -> RiskWeights:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    weights = raw.get("weights", {})
    return RiskWeights(
        level=float(weights.get("level", 40)),
        threat_intel=float(weights.get("threat_intel", 20)),
        foreign_country=float(weights.get("foreign_country", 15)),
        successful_login=float(weights.get("successful_login", 15)),
        recurrence=float(weights.get("recurrence", 10)),
        recurrence_saturation=int(raw.get("recurrence_saturation", 5)),
        level_factors={**DEFAULT_LEVEL_FACTORS, **raw.get("level_factors", {})},
    )


def score(inputs: RiskInputs, weights: RiskWeights) -> RiskScore:
    if inputs.is_known_malicious:
        intel = 1.0
    elif inputs.abuse_score is not None:
        intel = min(max(inputs.abuse_score, 0), 100) / 100
    else:
        intel = 0.0
    factors = {
        "level": weights.level_factors.get(inputs.level, 0.0),
        "threat_intel": intel,
        "foreign_country": float(inputs.foreign_country),
        "successful_login": float(inputs.successful_login),
        "recurrence": min(inputs.recent_alerts / max(weights.recurrence_saturation, 1), 1.0),
    }
    weighted = (
        weights.level * factors["level"]
        + weights.threat_intel * factors["threat_intel"]
        + weights.foreign_country * factors["foreign_country"]
        + weights.successful_login * factors["successful_login"]
        + weights.recurrence * factors["recurrence"]
    )
    value = round(100 * weighted / weights.total) if weights.total > 0 else 0
    return RiskScore(min(max(value, 0), 100), factors)
