from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

LEVEL_ORDER = ("informational", "low", "medium", "high", "critical")
TECHNIQUE_URL = "https://attack.mitre.org/techniques/{}/"


@dataclass(frozen=True, slots=True)
class Notification:
    subject: str
    text: str
    slack: dict[str, Any]


def level_rank(level: str) -> int:
    return LEVEL_ORDER.index(level) if level in LEVEL_ORDER else -1


def should_notify(alert: Mapping[str, Any], minimum_level: str) -> bool:
    return level_rank(str(alert.get("level"))) >= level_rank(minimum_level)


def _location(alert: Mapping[str, Any]) -> str:
    parts = [alert.get("city"), alert.get("country")]
    place = ", ".join(str(part) for part in parts if part)
    if alert.get("as_org"):
        place = f"{place} (AS{alert.get('asn')} {alert['as_org']})".strip()
    return place or "unknown"


def _intel(alert: Mapping[str, Any]) -> str:
    if alert.get("is_known_malicious"):
        score = alert.get("abuse_score")
        return "listed as malicious" + (f", abuse score {score}" if score is not None else "")
    if alert.get("abuse_score") is not None:
        return f"abuse score {alert['abuse_score']}"
    return "no threat intel match"


def dashboard_link(base_url: str, alert: Mapping[str, Any]) -> str:
    return (
        f"{base_url.rstrip('/')}/d/sentinelflow-alert-detail/alert-detail"
        f"?var-alert_id={quote(str(alert['alert_id']))}"
    )


def build(alert: Mapping[str, Any], grafana_url: str) -> Notification:
    level = str(alert.get("level", "unknown")).upper()
    entity = f"{alert.get('entity_type')} {alert.get('entity')}"
    techniques = list(alert.get("mitre_techniques") or [])
    tactics = ", ".join(alert.get("mitre_tactics") or []) or "n/a"
    link = dashboard_link(grafana_url, alert)
    subject = f"[{level}] {alert.get('rule_title')} - {entity} (risk {alert.get('risk_score')})"
    lines = [
        f"What happened: {alert.get('rule_title')}",
        f"Entity: {entity}",
        f"Risk score: {alert.get('risk_score')}/100",
        f"Level: {level}",
        f"MITRE ATT&CK: {', '.join(techniques) or 'n/a'} ({tactics})",
        f"First seen: {alert.get('first_seen')}",
        f"Last seen: {alert.get('last_seen')}",
        f"Events: {alert.get('event_count')}",
        f"Source location: {_location(alert)}",
        f"Threat intel: {_intel(alert)}",
        f"User: {alert.get('user_name') or 'n/a'}",
        "",
        "References:",
        *[f"  {TECHNIQUE_URL.format(technique.replace('.', '/'))}" for technique in techniques],
        "",
        f"Investigate: {link}",
        f"Alert id: {alert.get('alert_id')}",
    ]
    slack = {
        "text": subject,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": subject[:150]}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines[:11])}},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in Grafana"},
                        "url": link,
                    }
                ],
            },
        ],
    }
    return Notification(subject, "\n".join(lines), slack)
