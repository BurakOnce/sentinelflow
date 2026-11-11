import json
import logging
import os
import smtplib
import tempfile
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from notifier.messages import Notification, build, should_notify

LIVENESS_FILE = Path(tempfile.gettempdir()) / "notifier.alive"
logger = logging.getLogger(__name__)


class Channel(Protocol):
    def send(self, notification: Notification) -> None: ...


@dataclass(frozen=True, slots=True)
class EmailChannel:
    host: str
    port: int
    sender: str
    recipients: Sequence[str]

    def send(self, notification: Notification) -> None:
        message = EmailMessage()
        message["Subject"] = notification.subject
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message.set_content(notification.text)
        with smtplib.SMTP(self.host, self.port, timeout=10) as client:
            client.send_message(message)


@dataclass(frozen=True, slots=True)
class SlackChannel:
    webhook_url: str
    post: Callable[[str, bytes], int] = field(default=lambda url, body: _post(url, body))

    def send(self, notification: Notification) -> None:
        status = self.post(self.webhook_url, json.dumps(notification.slack).encode("utf-8"))
        if status >= 300:
            logger.warning("slack webhook returned HTTP %s", status)


def _post(url: str, body: bytes) -> int:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return int(response.status)


class Notifier:
    def __init__(self, channels: Sequence[Channel], minimum_level: str, grafana_url: str) -> None:
        self._channels = channels
        self._minimum_level = minimum_level
        self._grafana_url = grafana_url
        self._notified: set[str] = set()

    def handle(self, alert: Mapping[str, Any]) -> bool:
        alert_id = str(alert.get("alert_id"))
        if alert_id in self._notified or not should_notify(alert, self._minimum_level):
            return False
        notification = build(alert, self._grafana_url)
        for channel in self._channels:
            try:
                channel.send(notification)
            except Exception:
                logger.exception("failed to deliver alert %s via %s", alert_id, channel)
        self._notified.add(alert_id)
        return True


def channels_from_environment() -> list[Channel]:
    channels: list[Channel] = [
        EmailChannel(
            host=os.environ.get("SMTP_HOST", "localhost"),
            port=int(os.environ.get("SMTP_PORT", "1025")),
            sender=os.environ.get("ALERT_FROM_ADDRESS", "alerts@sentinelflow.local"),
            recipients=os.environ.get("ALERT_RECIPIENTS", "soc@sentinelflow.local").split(","),
        )
    ]
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if webhook:
        channels.append(SlackChannel(webhook))
    return channels


def main() -> None:
    from confluent_kafka import Consumer

    logging.basicConfig(level=logging.INFO)
    notifier = Notifier(
        channels_from_environment(),
        os.environ.get("NOTIFY_MIN_LEVEL", "high"),
        os.environ.get("GRAFANA_URL", "http://localhost:3000"),
    )
    consumer = Consumer(
        {
            "bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092"),
            "group.id": "sentinelflow-notifier",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,
        }
    )
    consumer.subscribe(["alerts"])
    logger.info("notifier listening on alerts")
    try:
        while True:
            LIVENESS_FILE.touch()
            message = consumer.poll(5.0)
            if message is None:
                continue
            if message.error():
                logger.warning("kafka error: %s", message.error())
                continue
            payload = message.value()
            if payload is None:
                continue
            try:
                alert = json.loads(payload)
            except ValueError:
                logger.warning("skipping malformed alert message")
                continue
            if notifier.handle(alert):
                logger.info("notified %s %s", alert.get("rule_name"), alert.get("entity"))
    finally:
        consumer.close()


if __name__ == "__main__":
    main()
