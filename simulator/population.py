import unicodedata
from dataclasses import dataclass
from random import Random

from faker import Faker

from simulator.events import MfaMethod
from simulator.geo import COUNTRIES, HOME_COUNTRY_WEIGHTS, City
from simulator.infrastructure import DESKTOP_USER_AGENTS, MOBILE_USER_AGENTS

FAKER_LOCALES = {"TR": "tr_TR", "DE": "de_DE", "GB": "en_GB", "US": "en_US"}
DEPARTMENTS = ("engineering", "finance", "sales", "support", "hr", "operations", "marketing")
SSH_DEPARTMENTS = frozenset({"engineering", "operations"})
TURKISH_TRANSLITERATION = str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosuCGIOSU")


@dataclass(frozen=True, slots=True)
class User:
    username: str
    full_name: str
    department: str
    uid: int
    city: City
    home_ip: str
    mobile_ip: str
    desktop_agent: str
    mobile_agent: str | None
    work_start_hour: float
    work_end_hour: float
    sessions_per_day: float
    typo_rate: float
    mfa: MfaMethod
    ssh_access: bool
    ssh_key_fingerprint: str

    @property
    def utc_offset_hours(self) -> int:
        return self.city.utc_offset_hours


def _ascii_slug(value: str) -> str:
    folded = unicodedata.normalize("NFKD", value.translate(TURKISH_TRANSLITERATION))
    return "".join(char for char in folded.lower() if char.isascii() and char.isalpha())


def _unique_username(first_name: str, last_name: str, taken: set[str]) -> str:
    base = f"{_ascii_slug(first_name)}.{_ascii_slug(last_name)}"
    candidate, suffix = base, 1
    while candidate in taken:
        suffix += 1
        candidate = f"{base}{suffix}"
    taken.add(candidate)
    return candidate


def _fingerprint(rng: Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(rng.choice(alphabet) for _ in range(43))


def build_population(seed: int, size: int) -> tuple[User, ...]:
    rng = Random(f"{seed}:population")
    faker = Faker(list(FAKER_LOCALES.values()))
    faker.seed_instance(seed)
    taken: set[str] = set()
    users: list[User] = []
    country_codes = list(HOME_COUNTRY_WEIGHTS)
    weights = list(HOME_COUNTRY_WEIGHTS.values())
    for index in range(size):
        country = COUNTRIES[rng.choices(country_codes, weights)[0]]
        locale_faker = faker[FAKER_LOCALES[country.code]]
        first_name, last_name = locale_faker.first_name(), locale_faker.last_name()
        department = rng.choice(DEPARTMENTS)
        work_start = min(max(rng.gauss(8.8, 0.6), 7.0), 10.5)
        users.append(
            User(
                username=_unique_username(first_name, last_name, taken),
                full_name=f"{first_name} {last_name}",
                department=department,
                uid=1001 + index,
                city=rng.choice(country.cities),
                home_ip=country.random_ip(rng),
                mobile_ip=country.random_ip(rng),
                desktop_agent=rng.choice(DESKTOP_USER_AGENTS),
                mobile_agent=rng.choice(MOBILE_USER_AGENTS) if rng.random() < 0.7 else None,
                work_start_hour=work_start,
                work_end_hour=work_start + min(max(rng.gauss(9.0, 0.7), 7.5), 11.0),
                sessions_per_day=rng.uniform(1.5, 4.0),
                typo_rate=rng.uniform(0.02, 0.08),
                mfa=rng.choices((MfaMethod.PUSH, MfaMethod.TOTP, MfaMethod.NONE), (6, 2, 2))[0],
                ssh_access=department in SSH_DEPARTMENTS and rng.random() < 0.8,
                ssh_key_fingerprint=_fingerprint(rng),
            )
        )
    return tuple(users)
