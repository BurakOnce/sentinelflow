from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pyarrow import fs

from detections.engine.alerts import AlertManager, alert_id
from detections.engine.hits import Hit
from detections.engine.loader import RuleSet, load_rules
from notifier.messages import Notification, build, dashboard_link, should_notify
from notifier.service import Notifier, SlackChannel

NOW = datetime(2026, 9, 28, 12, tzinfo=UTC)
ALERT_MESSAGE: dict[str, Any] = {
    "alert_id": "0f6d6c1e-2b3c-5d4e-8f9a-0b1c2d3e4f5a",
    "rule_name": "brute_force_success",
    "rule_title": "SSH Brute Force Followed By Successful Login",
    "level": "critical",
    "risk_score": 88,
    "entity_type": "ip",
    "entity": "36.100.2.3",
    "mitre_techniques": ["T1110.001", "T1078"],
    "mitre_tactics": ["credential-access", "initial-access"],
    "first_seen": "2026-09-28T12:00:00+00:00",
    "last_seen": "2026-09-28T12:01:10+00:00",
    "event_count": 61,
    "country": "China",
    "city": "Beijing",
    "asn": 4134,
    "as_org": "CHINANET-BACKBONE",
    "is_known_malicious": 1,
    "abuse_score": 92,
    "user_name": "ayse.yilmaz",
}


@pytest.fixture(scope="module")
def rules() -> RuleSet:
    return load_rules()


def hit(
    rules: RuleSet, minutes: float, entity: str = "36.100.2.3", ids: set[str] | None = None
) -> Hit:
    moment = NOW + timedelta(minutes=minutes)
    return Hit(
        rule_id=rules.by_name("ssh_bruteforce").meta.id,
        entity_type="ip",
        entity=entity,
        first_seen=moment,
        last_seen=moment + timedelta(seconds=30),
        detected_at=moment + timedelta(seconds=20),
        event_ids=frozenset(ids or {f"e{minutes}"}),
    )


def test_suppression_merges_hits_for_same_rule_and_entity(rules: RuleSet) -> None:
    manager = AlertManager(rules, timedelta(minutes=30))
    first = manager.apply([hit(rules, 0, ids={"a", "b"})])
    second = manager.apply([hit(rules, 10, ids={"b", "c"})])
    assert len(first) == len(second) == 1
    assert first[0].alert_id == second[0].alert_id
    assert second[0].event_count == 3
    assert second[0].last_seen == NOW + timedelta(minutes=10, seconds=30)
    assert second[0].detected_at == NOW + timedelta(seconds=20)
    assert len(manager.open_alerts()) == 1


def test_suppression_window_expiry_opens_new_alert(rules: RuleSet) -> None:
    manager = AlertManager(rules, timedelta(minutes=30))
    manager.apply([hit(rules, 0)])
    manager.apply([hit(rules, 45)])
    assert len(manager.open_alerts()) == 2


def test_different_entities_get_separate_alerts(rules: RuleSet) -> None:
    manager = AlertManager(rules, timedelta(minutes=30))
    manager.apply([hit(rules, 0), hit(rules, 1, entity="95.24.1.1")])
    assert {alert.entity for alert in manager.open_alerts()} == {"36.100.2.3", "95.24.1.1"}


def test_replayed_hits_do_not_change_alerts(rules: RuleSet) -> None:
    manager = AlertManager(rules, timedelta(minutes=30))
    batch = [hit(rules, 0, ids={"a"}), hit(rules, 5, ids={"b"})]
    manager.apply(batch)
    assert manager.apply(batch) == []
    assert manager.open_alerts()[0].event_count == 2


def test_alert_ids_are_deterministic(rules: RuleSet) -> None:
    assert alert_id(hit(rules, 0)) == alert_id(hit(rules, 0))
    assert alert_id(hit(rules, 0)) != alert_id(hit(rules, 1))


def test_restored_alerts_absorb_new_hits(rules: RuleSet) -> None:
    first = AlertManager(rules, timedelta(minutes=30))
    [alert] = first.apply([hit(rules, 0, ids={"a"})])
    second = AlertManager(rules, timedelta(minutes=30))
    second.restore([alert])
    [updated] = second.apply([hit(rules, 3, ids={"b"})])
    assert updated.alert_id == alert.alert_id
    assert updated.event_count == 2


def test_default_suppression_applies_without_rule_override(rules: RuleSet) -> None:
    manager = AlertManager(rules, timedelta(minutes=5))
    assert manager.suppression(rules.by_name("ssh_bruteforce").meta.id) == timedelta(minutes=5)


def test_notification_contains_analyst_context() -> None:
    notification = build(ALERT_MESSAGE, "http://grafana.local")
    assert notification.subject.startswith(
        "[CRITICAL] SSH Brute Force Followed By Successful Login"
    )
    assert "ip 36.100.2.3" in notification.subject
    for expected in (
        "Risk score: 88/100",
        "T1110.001, T1078",
        "Beijing, China (AS4134 CHINANET-BACKBONE)",
        "listed as malicious, abuse score 92",
        "https://attack.mitre.org/techniques/T1110/001/",
        dashboard_link("http://grafana.local", ALERT_MESSAGE),
    ):
        assert expected in notification.text
    assert notification.slack["blocks"][2]["elements"][0]["url"].startswith(
        "http://grafana.local/d/"
    )


@pytest.mark.parametrize(
    ("level", "minimum", "expected"),
    [
        ("critical", "high", True),
        ("high", "high", True),
        ("medium", "high", False),
        ("low", "low", True),
    ],
)
def test_notification_level_threshold(level: str, minimum: str, expected: bool) -> None:
    assert should_notify({"level": level}, minimum) is expected


class RecordingChannel:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[Notification] = []
        self.fail = fail

    def send(self, notification: Notification) -> None:
        if self.fail:
            raise OSError("smtp down")
        self.sent.append(notification)


def test_notifier_sends_each_alert_once_and_survives_channel_errors() -> None:
    working, broken = RecordingChannel(), RecordingChannel(fail=True)
    notifier = Notifier([broken, working], "high", "http://grafana.local")
    assert notifier.handle(ALERT_MESSAGE)
    assert not notifier.handle(ALERT_MESSAGE | {"event_count": 70})
    assert not notifier.handle(ALERT_MESSAGE | {"alert_id": "other", "level": "medium"})
    assert len(working.sent) == 1


def test_slack_channel_posts_block_payload() -> None:
    posted: list[tuple[str, bytes]] = []

    def post(url: str, body: bytes) -> int:
        posted.append((url, body))
        return 200

    channel = SlackChannel("https://hooks.example/abc", post=post)
    channel.send(build(ALERT_MESSAGE, "http://grafana.local"))
    assert posted[0][0] == "https://hooks.example/abc"
    assert b'"blocks"' in posted[0][1]


def write_parquet(path: str, rows: list[dict[str, Any]], filesystem: fs.FileSystem) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    filesystem.create_dir(path.rsplit("/", 1)[0], recursive=True)
    pq.write_table(pa.Table.from_pylist(rows), path, filesystem=filesystem)


def test_compaction_merges_and_deduplicates_a_day(tmp_path: Path) -> None:
    import pyarrow.parquet as pq

    from orchestration.lake import LakeLocation, compact_day

    local = fs.LocalFileSystem()
    location = LakeLocation(local, tmp_path.as_posix())
    base = f"{tmp_path.as_posix()}/events/source_type=ssh/event_date=2026-09-28"
    rows = [
        {"event_id": f"e{index}", "timestamp": NOW + timedelta(seconds=index)} for index in range(4)
    ]
    write_parquet(f"{base}/part-1.parquet", rows[:3], local)
    write_parquet(f"{base}/part-2.parquet", rows[2:], local)
    write_parquet(
        f"{tmp_path.as_posix()}/events/source_type=ssh/event_date=2026-09-29/part-1.parquet",
        rows[:1],
        local,
    )
    written = compact_day(location, location, NOW.date())
    compacted = pq.read_table(
        f"{tmp_path.as_posix()}/events_daily/source_type=ssh/event_date=2026-09-28/part-00000.parquet"
    )
    assert written == {"ssh": 4}
    assert compacted.column("event_id").to_pylist() == ["e0", "e1", "e2", "e3"]


def test_bronze_retention_removes_only_expired_partitions(tmp_path: Path) -> None:
    from orchestration.lake import LakeLocation, expire_partitions

    local = fs.LocalFileSystem()
    location = LakeLocation(local, tmp_path.as_posix())
    for day in ("2026-08-01", "2026-09-20", "2026-09-28"):
        write_parquet(
            f"{tmp_path.as_posix()}/raw_logs/source_type=nginx/ingest_date={day}/part.parquet",
            [{"raw_message": "x"}],
            local,
        )
    removed = expire_partitions(location, "raw_logs", "ingest_date", 30, NOW.date())
    assert [path.rsplit("=", 1)[-1] for path in removed] == ["2026-08-01"]
    assert (tmp_path / "raw_logs/source_type=nginx/ingest_date=2026-09-20").exists()


def test_ground_truth_sensor_cursor_changes_with_file(tmp_path: Path) -> None:
    from orchestration.sensors import labels_cursor

    labels = tmp_path / "ground_truth.jsonl"
    assert labels_cursor(labels) is None
    labels.write_text("{}\n", encoding="utf-8")
    first = labels_cursor(labels)
    labels.write_text("{}\n{}\n", encoding="utf-8")
    assert labels_cursor(labels) not in {None, first}
