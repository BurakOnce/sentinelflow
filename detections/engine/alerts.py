import threading
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

from detections.engine.hits import Hit
from detections.engine.loader import RuleSet
from detections.engine.model import CorrelationRule, DetectorRule, Rule

ALERT_NAMESPACE = uuid.UUID("4f1c7c1e-4a8e-4b5b-9d55-3f0c1f5f2a10")
SAMPLE_SIZE = 10
MAX_EVENT_IDS = 10_000
RETENTION_MARGIN = timedelta(hours=24)
AlertKey = tuple[str, str, str]


def rule_type(rule: Rule) -> str:
    if isinstance(rule, CorrelationRule):
        return "correlation"
    if isinstance(rule, DetectorRule):
        return "detector"
    return "single"


@dataclass(slots=True)
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    rule_title: str
    rule_type: str
    level: str
    mitre_tactics: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    entity_type: str
    entity: str
    first_seen: datetime
    last_seen: datetime
    detected_at: datetime
    event_ids: dict[str, None]
    overflow_count: int = 0
    status: str = "new"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_ip: str | None = None
    user_name: str | None = None
    has_success: bool = False

    @property
    def key(self) -> AlertKey:
        return (self.rule_id, self.entity_type, self.entity)

    @property
    def event_count(self) -> int:
        return len(self.event_ids) + self.overflow_count

    @property
    def sample_event_ids(self) -> list[str]:
        return list(self.event_ids)[:SAMPLE_SIZE]

    def snapshot(self) -> "Alert":
        return replace(self, event_ids=dict(self.event_ids))


def alert_id(hit: Hit) -> str:
    identity = f"{hit.rule_id}|{hit.entity_type}|{hit.entity}|{hit.first_seen.isoformat()}"
    return str(uuid.uuid5(ALERT_NAMESPACE, identity))


class AlertManager:
    def __init__(
        self,
        rules: RuleSet,
        default_suppression: timedelta,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._rules = {rule.meta.id: rule for rule in rules.rules}
        self._default_suppression = default_suppression
        self._clock = clock
        self._alerts: defaultdict[AlertKey, list[Alert]] = defaultdict(list)
        self._lock = threading.Lock()
        self._high_water = datetime.min.replace(tzinfo=UTC)

    def suppression(self, rule_id: str) -> timedelta:
        return self._rules[rule_id].suppression or self._default_suppression

    def restore(self, alerts: Iterable[Alert]) -> None:
        with self._lock:
            for alert in alerts:
                self._alerts[alert.key].append(alert)
                self._high_water = max(self._high_water, alert.last_seen)

    def open_alerts(self) -> list[Alert]:
        with self._lock:
            return [alert.snapshot() for alerts in self._alerts.values() for alert in alerts]

    def recent_alerts(self, entity_type: str, entity: str, since: datetime) -> int:
        with self._lock:
            return sum(
                1
                for (_, kind, value), alerts in self._alerts.items()
                if kind == entity_type and value == entity
                for alert in alerts
                if alert.last_seen >= since
            )

    def _new_alert(self, hit: Hit, now: datetime) -> Alert:
        rule = self._rules[hit.rule_id]
        ids = sorted(hit.event_ids)[:MAX_EVENT_IDS]
        return Alert(
            alert_id=alert_id(hit),
            rule_id=rule.meta.id,
            rule_name=rule.meta.name,
            rule_title=rule.meta.title,
            rule_type=rule_type(rule),
            level=str(rule.meta.level),
            mitre_tactics=rule.meta.tactics,
            mitre_techniques=rule.meta.techniques,
            entity_type=hit.entity_type,
            entity=hit.entity,
            first_seen=hit.first_seen,
            last_seen=hit.last_seen,
            detected_at=hit.detected_at,
            event_ids=dict.fromkeys(ids),
            overflow_count=len(hit.event_ids) - len(ids),
            created_at=now,
            updated_at=now,
            source_ip=hit.source_ip,
            user_name=hit.user_name,
            has_success=hit.has_success,
        )

    @staticmethod
    def _merge(alert: Alert, hit: Hit, now: datetime) -> bool:
        new_ids = [
            event_id for event_id in sorted(hit.event_ids) if event_id not in alert.event_ids
        ]
        changed = bool(new_ids)
        room = max(MAX_EVENT_IDS - len(alert.event_ids), 0)
        alert.event_ids.update(dict.fromkeys(new_ids[:room]))
        alert.overflow_count += len(new_ids[room:])
        if hit.first_seen < alert.first_seen:
            alert.first_seen, changed = hit.first_seen, True
        if hit.last_seen > alert.last_seen:
            alert.last_seen, changed = hit.last_seen, True
            alert.source_ip = hit.source_ip or alert.source_ip
            alert.user_name = hit.user_name or alert.user_name
        if hit.detected_at < alert.detected_at:
            alert.detected_at, changed = hit.detected_at, True
        if hit.has_success and not alert.has_success:
            alert.has_success, changed = True, True
        if changed:
            alert.updated_at = max(now, alert.updated_at + timedelta(milliseconds=1))
        return changed

    def apply(self, hits: Iterable[Hit]) -> list[Alert]:
        now = self._clock()
        changed: dict[str, Alert] = {}
        with self._lock:
            for hit in sorted(hits, key=lambda item: (item.first_seen, item.rule_id)):
                window = self.suppression(hit.rule_id)
                candidates = self._alerts[(hit.rule_id, hit.entity_type, hit.entity)]
                target = next(
                    (
                        alert
                        for alert in candidates
                        if hit.first_seen <= alert.last_seen + window
                        and hit.last_seen >= alert.first_seen - window
                    ),
                    None,
                )
                if target is None:
                    target = self._new_alert(hit, now)
                    candidates.append(target)
                    changed[target.alert_id] = target
                elif self._merge(target, hit, now):
                    changed[target.alert_id] = target
                self._high_water = max(self._high_water, hit.last_seen)
            self._evict()
            return [alert.snapshot() for alert in changed.values()]

    def _evict(self) -> None:
        for key in list(self._alerts):
            horizon = self._high_water - self.suppression(key[0]) - RETENTION_MARGIN
            kept = [alert for alert in self._alerts[key] if alert.last_seen >= horizon]
            if kept:
                self._alerts[key] = kept
            else:
                del self._alerts[key]
