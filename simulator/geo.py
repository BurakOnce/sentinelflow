import math
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from random import Random

EARTH_RADIUS_KM = 6371.0


@dataclass(frozen=True, slots=True)
class City:
    name: str
    country_code: str
    latitude: float
    longitude: float
    utc_offset_hours: int


@dataclass(frozen=True, slots=True)
class Country:
    code: str
    name: str
    networks: tuple[IPv4Network, ...]
    cities: tuple[City, ...]

    def random_ip(self, rng: Random) -> str:
        network = rng.choice(self.networks)
        offset = rng.randrange(1, network.num_addresses - 1)
        return str(IPv4Address(int(network.network_address) + offset))

    def locate(self, ip: str) -> bool:
        address = IPv4Address(ip)
        return any(address in network for network in self.networks)


def _networks(*cidrs: str) -> tuple[IPv4Network, ...]:
    return tuple(IPv4Network(cidr) for cidr in cidrs)


def _country(
    code: str, name: str, cidrs: tuple[str, ...], cities: tuple[tuple[str, float, float, int], ...]
) -> Country:
    return Country(
        code=code,
        name=name,
        networks=_networks(*cidrs),
        cities=tuple(City(city, code, lat, lon, offset) for city, lat, lon, offset in cities),
    )


COUNTRIES: dict[str, Country] = {
    country.code: country
    for country in (
        _country(
            "TR",
            "Turkey",
            ("78.160.0.0/11", "88.224.0.0/11", "85.96.0.0/12", "95.0.0.0/12"),
            (
                ("Istanbul", 41.0082, 28.9784, 3),
                ("Ankara", 39.9334, 32.8597, 3),
                ("Izmir", 38.4237, 27.1428, 3),
                ("Bursa", 40.1885, 29.0610, 3),
                ("Antalya", 36.8969, 30.7133, 3),
                ("Kocaeli", 40.8533, 29.8815, 3),
            ),
        ),
        _country(
            "DE",
            "Germany",
            ("79.192.0.0/10", "84.128.0.0/10", "91.0.0.0/10"),
            (("Berlin", 52.5200, 13.4050, 2), ("Munich", 48.1351, 11.5820, 2)),
        ),
        _country(
            "GB",
            "United Kingdom",
            ("86.128.0.0/10", "2.24.0.0/13"),
            (("London", 51.5074, -0.1278, 1),),
        ),
        _country(
            "US",
            "United States",
            ("73.0.0.0/8", "67.160.0.0/11"),
            (("New York", 40.7128, -74.0060, -4), ("San Francisco", 37.7749, -122.4194, -7)),
        ),
        _country(
            "CN",
            "China",
            ("36.96.0.0/11", "117.136.0.0/13"),
            (("Beijing", 39.9042, 116.4074, 8), ("Shanghai", 31.2304, 121.4737, 8)),
        ),
        _country(
            "RU",
            "Russia",
            ("95.24.0.0/13", "5.136.0.0/13"),
            (("Moscow", 55.7558, 37.6173, 3), ("Novosibirsk", 55.0084, 82.9357, 7)),
        ),
        _country(
            "BR",
            "Brazil",
            ("177.32.0.0/11", "187.0.0.0/11"),
            (("Sao Paulo", -23.5505, -46.6333, -3),),
        ),
        _country(
            "VN",
            "Vietnam",
            ("113.160.0.0/11", "14.160.0.0/11"),
            (("Hanoi", 21.0278, 105.8342, 7),),
        ),
        _country(
            "IN",
            "India",
            ("117.192.0.0/10", "59.88.0.0/13"),
            (("Mumbai", 19.0760, 72.8777, 5),),
        ),
        _country(
            "JP",
            "Japan",
            ("126.0.0.0/8",),
            (("Tokyo", 35.6762, 139.6503, 9),),
        ),
        _country(
            "AU",
            "Australia",
            ("1.120.0.0/13", "101.160.0.0/11"),
            (("Sydney", -33.8688, 151.2093, 10),),
        ),
    )
}

HOME_COUNTRY_WEIGHTS: dict[str, float] = {"TR": 0.85, "DE": 0.06, "GB": 0.04, "US": 0.05}
HOSTILE_COUNTRIES: tuple[str, ...] = ("CN", "RU", "BR", "VN", "IN")
DISTANT_COUNTRIES: tuple[str, ...] = ("US", "BR", "JP", "AU", "CN")


def distance_km(first: City, second: City) -> float:
    lat1, lon1 = math.radians(first.latitude), math.radians(first.longitude)
    lat2, lon2 = math.radians(second.latitude), math.radians(second.longitude)
    half_chord = (
        math.sin((lat2 - lat1) / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    )
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(half_chord))


def country_of(ip: str) -> Country | None:
    return next((country for country in COUNTRIES.values() if country.locate(ip)), None)
