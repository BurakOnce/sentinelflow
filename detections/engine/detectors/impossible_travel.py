from collections.abc import Sequence
from datetime import datetime

from detections.engine.detectors.base import Event, StateStore, register
from detections.engine.hits import Hit
from detections.engine.model import DetectorRule, entity_type
from enrichment.geo import GeoLocation, GeoLookup, haversine_km

NAME = "impossible_travel"


def _location(state: dict[str, object]) -> GeoLocation:
    return GeoLocation(
        country_code=str(state["country_code"]),
        country=str(state["country"]),
        city=str(state["city"]),
        latitude=float(str(state["latitude"])),
        longitude=float(str(state["longitude"])),
        asn=int(str(state["asn"])) if state.get("asn") is not None else None,
    )


@register(NAME)
def impossible_travel(
    rule: DetectorRule, events: Sequence[Event], state: StateStore, geo: GeoLookup
) -> list[Hit]:
    max_speed = float(rule.parameters.get("max_speed_kmh", 900))
    min_distance = float(rule.parameters.get("min_distance_km", 500))
    min_domestic_distance = float(rule.parameters.get("min_domestic_distance_km", min_distance))
    ignore_same_asn = rule.parameters.get("ignore_same_asn", False) is True
    ordered = sorted(events, key=lambda event: (event["timestamp"], event["event_id"]))
    located = geo.locate(str(event["source_ip"]) for event in ordered if event.get("source_ip"))
    hits = []
    for event in ordered:
        user = event.get(rule.entity_field)
        location = located.get(str(event.get("source_ip")))
        if user is None or location is None:
            continue
        moment: datetime = event["timestamp"]
        previous = state.get(NAME, str(user))
        if previous is not None and moment <= datetime.fromisoformat(str(previous["timestamp"])):
            continue
        state.put(
            NAME,
            str(user),
            {
                "timestamp": moment.isoformat(),
                "event_id": event["event_id"],
                "source_ip": event["source_ip"],
                "country_code": location.country_code,
                "country": location.country,
                "city": location.city,
                "latitude": location.latitude,
                "longitude": location.longitude,
                "asn": location.asn,
            },
        )
        if previous is None:
            continue
        origin = _location(previous)
        distance = haversine_km(origin, location)
        started = datetime.fromisoformat(str(previous["timestamp"]))
        hours = (moment - started).total_seconds() / 3600
        domestic = origin.country_code == location.country_code
        threshold = min_domestic_distance if domestic else min_distance
        if distance < threshold or (hours > 0 and distance / hours <= max_speed):
            continue
        if ignore_same_asn and origin.asn is not None and origin.asn == location.asn:
            continue
        hits.append(
            Hit(
                rule_id=rule.meta.id,
                entity_type=entity_type(rule.entity_field),
                entity=str(user),
                first_seen=started,
                last_seen=moment,
                detected_at=moment,
                event_ids=frozenset({str(previous["event_id"]), str(event["event_id"])}),
                source_ip=str(event["source_ip"]),
                user_name=str(user),
                has_success=True,
            )
        )
    return hits
