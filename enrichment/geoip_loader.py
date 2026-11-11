import csv
import gzip
import io
import urllib.request
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from ipaddress import IPv4Address, summarize_address_range
from itertools import islice
from pathlib import Path

from clickhouse_connect.driver.client import Client

from enrichment.geo import ASN_FIXTURE, CITY_FIXTURE, read_asn_rows, read_city_rows

DBIP_BASE_URL = "https://download.db-ip.com/free"
BATCH_SIZE = 100_000
CITY_COLUMNS = ("network", "country_code", "country", "city", "latitude", "longitude", "source")
ASN_COLUMNS = ("network", "asn", "as_org", "source")


def dbip_urls(month: str) -> tuple[str, str]:
    return (
        f"{DBIP_BASE_URL}/dbip-city-lite-{month}.csv.gz",
        f"{DBIP_BASE_URL}/dbip-asn-lite-{month}.csv.gz",
    )


def download(url: str, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "sentinelflow"})
    with urllib.request.urlopen(request, timeout=300) as response, target.open("wb") as handle:
        while chunk := response.read(1 << 20):
            handle.write(chunk)
    return target


def download_dbip(directory: Path, month: str | None = None) -> tuple[Path, Path]:
    period = month or datetime.now(UTC).strftime("%Y-%m")
    city_url, asn_url = dbip_urls(period)
    return (
        download(city_url, directory / f"dbip-city-lite-{period}.csv.gz"),
        download(asn_url, directory / f"dbip-asn-lite-{period}.csv.gz"),
    )


def _ipv4_networks(start: str, end: str) -> list[str]:
    try:
        first, last = IPv4Address(start), IPv4Address(end)
    except ValueError:
        return []
    return [str(network) for network in summarize_address_range(first, last)]


def _csv_rows(path: Path) -> Iterator[list[str]]:
    with gzip.open(path, "rb") as compressed:
        yield from csv.reader(io.TextIOWrapper(compressed, encoding="utf-8"))


def dbip_city_rows(path: Path) -> Iterator[tuple[str, str, str, str, float, float]]:
    for row in _csv_rows(path):
        start, end, _continent, country, _region, city, latitude, longitude = row[:8]
        for network in _ipv4_networks(start, end):
            yield network, country, country, city, float(latitude), float(longitude)


def dbip_asn_rows(path: Path) -> Iterator[tuple[str, int, str]]:
    for row in _csv_rows(path):
        start, end, asn, organization = row[:4]
        for network in _ipv4_networks(start, end):
            yield network, int(asn), organization


def _batches[T](rows: Iterable[T], size: int = BATCH_SIZE) -> Iterator[list[T]]:
    iterator = iter(rows)
    while batch := list(islice(iterator, size)):
        yield batch


def replace_networks(
    client: Client,
    cities: Iterable[tuple[str, str, str, str, float, float]],
    asns: Iterable[tuple[str, int, str]],
    source: str,
) -> tuple[int, int]:
    client.command("TRUNCATE TABLE IF EXISTS geoip_city_networks")
    client.command("TRUNCATE TABLE IF EXISTS geoip_asn_networks")
    city_count = asn_count = 0
    for city_batch in _batches(cities):
        client.insert(
            "geoip_city_networks",
            [[*row, source] for row in city_batch],
            column_names=list(CITY_COLUMNS),
        )
        city_count += len(city_batch)
    for asn_batch in _batches(asns):
        client.insert(
            "geoip_asn_networks",
            [[*row, source] for row in asn_batch],
            column_names=list(ASN_COLUMNS),
        )
        asn_count += len(asn_batch)
    client.command("SYSTEM RELOAD DICTIONARY geoip_city")
    client.command("SYSTEM RELOAD DICTIONARY geoip_asn")
    return city_count, asn_count


def load_fixture(client: Client) -> tuple[int, int]:
    return replace_networks(
        client, read_city_rows(CITY_FIXTURE), read_asn_rows(ASN_FIXTURE), "fixture"
    )


def load_dbip(client: Client, city_path: Path, asn_path: Path) -> tuple[int, int]:
    return replace_networks(client, dbip_city_rows(city_path), dbip_asn_rows(asn_path), "dbip")


def loaded_source(client: Client) -> str | None:
    rows = client.query("SELECT any(source) FROM geoip_city_networks").result_rows
    return rows[0][0] or None if rows else None
