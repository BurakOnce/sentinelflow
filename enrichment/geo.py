import csv
import math
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Protocol

from clickhouse_connect.driver.client import Client

EARTH_RADIUS_KM = 6371.0
FIXTURE_DIR = Path(__file__).parent / "fixtures"
CITY_FIXTURE = FIXTURE_DIR / "geoip_city.csv"
ASN_FIXTURE = FIXTURE_DIR / "geoip_asn.csv"


@dataclass(frozen=True, slots=True)
class GeoLocation:
    country_code: str
    country: str
    city: str
    latitude: float
    longitude: float
    asn: int | None = None
    as_org: str | None = None


class GeoLookup(Protocol):
    def locate(self, ips: Iterable[str]) -> dict[str, GeoLocation]: ...


def haversine_km(first: GeoLocation, second: GeoLocation) -> float:
    lat1, lon1 = math.radians(first.latitude), math.radians(first.longitude)
    lat2, lon2 = math.radians(second.latitude), math.radians(second.longitude)
    half_chord = (
        math.sin((lat2 - lat1) / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(half_chord))


def _is_ipv4(value: str) -> bool:
    try:
        IPv4Address(value)
    except ValueError:
        return False
    return True


class NetworkTableGeoLookup:
    def __init__(
        self,
        cities: Iterable[tuple[str, str, str, str, float, float]],
        asns: Iterable[tuple[str, int, str]] = (),
    ) -> None:
        self._cities = self._index(
            (network, (code, country, city, lat, lon))
            for network, code, country, city, lat, lon in cities
        )
        self._asns = self._index((network, (asn, org)) for network, asn, org in asns)

    @staticmethod
    def _index[T](rows: Iterable[tuple[str, T]]) -> tuple[list[int], list[int], list[T]]:
        ranges = []
        for text, value in rows:
            network = IPv4Network(text, strict=False)
            ranges.append((int(network.network_address), int(network.broadcast_address), value))
        ranges.sort(key=lambda row: row[0])
        return [row[0] for row in ranges], [row[1] for row in ranges], [row[2] for row in ranges]

    @staticmethod
    def _find[T](index: tuple[list[int], list[int], list[T]], address: int) -> T | None:
        starts, ends, values = index
        position = bisect_right(starts, address) - 1
        if position >= 0 and address <= ends[position]:
            return values[position]
        return None

    def locate(self, ips: Iterable[str]) -> dict[str, GeoLocation]:
        located: dict[str, GeoLocation] = {}
        for ip in set(ips):
            if not _is_ipv4(ip):
                continue
            address = int(IPv4Address(ip))
            city = self._find(self._cities, address)
            if city is None:
                continue
            asn = self._find(self._asns, address)
            located[ip] = GeoLocation(
                *city, asn=asn[0] if asn else None, as_org=asn[1] if asn else None
            )
        return located

    @classmethod
    def from_fixtures(
        cls, city_path: Path = CITY_FIXTURE, asn_path: Path = ASN_FIXTURE
    ) -> "NetworkTableGeoLookup":
        return cls(read_city_rows(city_path), read_asn_rows(asn_path))


def read_city_rows(path: Path) -> list[tuple[str, str, str, str, float, float]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [
            (
                row["network"],
                row["country_code"],
                row["country"],
                row["city"],
                float(row["latitude"]),
                float(row["longitude"]),
            )
            for row in csv.DictReader(handle)
        ]


def read_asn_rows(path: Path) -> list[tuple[str, int, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return [(row["network"], int(row["asn"]), row["as_org"]) for row in csv.DictReader(handle)]


class ClickHouseGeoLookup:
    def __init__(self, client: Client) -> None:
        self._client = client

    def locate(self, ips: Iterable[str]) -> dict[str, GeoLocation]:
        addresses = sorted({ip for ip in ips if _is_ipv4(ip)})
        if not addresses:
            return {}
        result = self._client.query(
            """
            SELECT
                ip,
                dictGet('geoip_city', 'country_code', toIPv4(ip)) AS country_code,
                dictGet('geoip_city', 'country', toIPv4(ip)) AS country,
                dictGet('geoip_city', 'city', toIPv4(ip)) AS city,
                dictGet('geoip_city', 'latitude', toIPv4(ip)) AS latitude,
                dictGet('geoip_city', 'longitude', toIPv4(ip)) AS longitude,
                dictGet('geoip_asn', 'asn', toIPv4(ip)) AS asn,
                dictGet('geoip_asn', 'as_org', toIPv4(ip)) AS as_org
            FROM (SELECT arrayJoin({ips:Array(String)}) AS ip)
            """,
            parameters={"ips": addresses},
        )
        located = {}
        for ip, code, country, city, latitude, longitude, asn, as_org in result.result_rows:
            if not code:
                continue
            located[ip] = GeoLocation(
                code, country, city, latitude, longitude, asn or None, as_org or None
            )
        return located
