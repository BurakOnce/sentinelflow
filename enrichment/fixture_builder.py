import csv
import sys
from ipaddress import IPv4Network
from pathlib import Path

from enrichment.geo import ASN_FIXTURE, CITY_FIXTURE
from simulator.geo import COUNTRIES

SUBNET_BITS = 3
NETWORK_OWNERS: dict[str, tuple[int, str]] = {
    "78.160.0.0/11": (9121, "Turk Telekom"),
    "88.224.0.0/11": (9121, "Turk Telekom"),
    "85.96.0.0/12": (9121, "Turk Telekom"),
    "95.0.0.0/12": (9121, "Turk Telekom"),
    "79.192.0.0/10": (3320, "Deutsche Telekom AG"),
    "84.128.0.0/10": (3320, "Deutsche Telekom AG"),
    "91.0.0.0/10": (3320, "Deutsche Telekom AG"),
    "86.128.0.0/10": (2856, "British Telecommunications PLC"),
    "2.24.0.0/13": (5607, "Sky UK Limited"),
    "73.0.0.0/8": (7922, "Comcast Cable Communications, LLC"),
    "67.160.0.0/11": (7922, "Comcast Cable Communications, LLC"),
    "36.96.0.0/11": (4134, "CHINANET-BACKBONE"),
    "117.136.0.0/13": (9808, "China Mobile Communications Group"),
    "95.24.0.0/13": (3216, "PJSC VimpelCom"),
    "5.136.0.0/13": (12389, "PJSC Rostelecom"),
    "177.32.0.0/11": (28573, "Claro NXT Telecomunicacoes Ltda"),
    "187.0.0.0/11": (18881, "Telefonica Brasil S.A"),
    "113.160.0.0/11": (45899, "VNPT Corp"),
    "14.160.0.0/11": (45899, "VNPT Corp"),
    "117.192.0.0/10": (9829, "Bharat Sanchar Nigam Limited"),
    "59.88.0.0/13": (9829, "Bharat Sanchar Nigam Limited"),
    "126.0.0.0/8": (17676, "SoftBank Corp."),
    "1.120.0.0/13": (1221, "Telstra Limited"),
    "101.160.0.0/11": (1221, "Telstra Limited"),
}


def city_rows() -> list[list[str]]:
    rows = []
    for country in COUNTRIES.values():
        for network in country.networks:
            for index, subnet in enumerate(network.subnets(prefixlen_diff=SUBNET_BITS)):
                city = country.cities[index % len(country.cities)]
                rows.append(
                    [
                        str(subnet),
                        country.code,
                        country.name,
                        city.name,
                        f"{city.latitude:.4f}",
                        f"{city.longitude:.4f}",
                    ]
                )
    return rows


def asn_rows() -> list[list[str]]:
    rows = []
    for country in COUNTRIES.values():
        for network in country.networks:
            asn, organization = NETWORK_OWNERS[str(network)]
            rows.append([str(IPv4Network(network)), str(asn), organization])
    return rows


def write(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    write(
        CITY_FIXTURE,
        ["network", "country_code", "country", "city", "latitude", "longitude"],
        city_rows(),
    )
    write(ASN_FIXTURE, ["network", "asn", "as_org"], asn_rows())
    sys.stdout.write(f"wrote {CITY_FIXTURE} and {ASN_FIXTURE}\n")


if __name__ == "__main__":
    main()
