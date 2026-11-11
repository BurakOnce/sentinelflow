from collections import Counter
from typing import Any

import pytest
from detection_support import (
    ATTACKER,
    app_login,
    firewall,
    normalized,
    request,
    scenario_events,
    ssh,
    ssh_failures,
)

from detections.engine.alerts import Alert
from detections.engine.loader import RuleSet, load_rules
from detections.engine.runner import evaluate
from enrichment.geo import NetworkTableGeoLookup
from simulator.events import AuthResult, SshEventKind

GEO = NetworkTableGeoLookup.from_fixtures()
ISTANBUL_IP = "78.160.10.10"
ANKARA_IP = "78.164.10.10"
NEW_YORK_IP = "73.0.10.10"
SCENARIO_RULES = {
    "ssh_bruteforce": {"ssh_bruteforce"},
    "password_spraying": {"password_spraying"},
    "credential_stuffing": {"credential_stuffing"},
    "brute_force_success": {"brute_force_success", "ssh_bruteforce"},
    "port_scan": {"port_scan"},
    "web_attack": {"web_attack_pattern", "scanner_user_agent"},
    "impossible_travel": {"impossible_travel"},
}


@pytest.fixture(scope="module")
def rules() -> RuleSet:
    return load_rules()


def fired(rules: RuleSet, events: list[dict[str, Any]]) -> Counter[str]:
    return Counter(alert.rule_name for alert in evaluate(rules, events, GEO))


def alerts_for(rules: RuleSet, events: list[dict[str, Any]], name: str) -> list[Alert]:
    return [alert for alert in evaluate(rules, events, GEO) if alert.rule_name == name]


def test_alerting_rule_catalogue(rules: RuleSet) -> None:
    assert {rule.meta.name for rule in rules.alerting} == set().union(*SCENARIO_RULES.values())
    assert len(rules.correlations) == 5
    assert [rule.meta.name for rule in rules.detectors] == ["impossible_travel"]


def test_ssh_bruteforce_fires_at_fifteen_failures(rules: RuleSet) -> None:
    alerts = alerts_for(rules, normalized(ssh_failures(15, 10)), "ssh_bruteforce")
    assert len(alerts) == 1
    assert (alerts[0].entity_type, alerts[0].entity) == ("ip", ATTACKER)
    assert alerts[0].event_count == 15
    assert alerts[0].mitre_techniques == ("T1110.001",)


def test_ssh_bruteforce_ignores_fourteen_failures(rules: RuleSet) -> None:
    assert fired(rules, normalized(ssh_failures(14, 10)))["ssh_bruteforce"] == 0


def test_ssh_bruteforce_ignores_slow_guessing(rules: RuleSet) -> None:
    assert fired(rules, normalized(ssh_failures(20, 60)))["ssh_bruteforce"] == 0


def test_ssh_bruteforce_ignores_occasional_typos(rules: RuleSet) -> None:
    events = []
    for day_offset in range(20):
        base = day_offset * 1800
        events += [
            ssh(base, SshEventKind.FAILED_PASSWORD, "ayse.yilmaz", ISTANBUL_IP),
            ssh(base + 5, SshEventKind.ACCEPTED_PASSWORD, "ayse.yilmaz", ISTANBUL_IP),
        ]
    assert fired(rules, normalized(events)) == Counter()


def test_password_spraying_counts_distinct_accounts(rules: RuleSet) -> None:
    events = normalized(app_login(index * 20, f"user{index}") for index in range(5))
    alerts = alerts_for(rules, events, "password_spraying")
    assert len(alerts) == 1
    assert alerts[0].entity == ATTACKER


def test_password_spraying_needs_five_accounts(rules: RuleSet) -> None:
    events = normalized(app_login(index * 20, f"user{index}") for index in range(4))
    assert fired(rules, events)["password_spraying"] == 0


def test_password_spraying_ignores_single_account_guessing(rules: RuleSet) -> None:
    events = normalized(app_login(index * 5, "mehmet.kaya") for index in range(30))
    assert fired(rules, events)["password_spraying"] == 0


def test_password_spraying_ignores_busy_shared_gateway(rules: RuleSet) -> None:
    office = "78.160.200.1"
    logins = [
        app_login(index * 15, f"user{index}", office, AuthResult.SUCCESS) for index in range(30)
    ]
    typos = [app_login(index * 15 + 5, f"user{index}", office) for index in range(3)]
    assert fired(rules, normalized([*logins, *typos]))["password_spraying"] == 0


def test_password_spraying_ignores_rotating_clients(rules: RuleSet) -> None:
    events = normalized(
        app_login(index * 20, f"user{index}", agent=f"Mozilla/5.0 client-{index}")
        for index in range(12)
    )
    assert fired(rules, events)["password_spraying"] == 0


def test_credential_stuffing_needs_many_sources_and_failures(rules: RuleSet) -> None:
    events = normalized(
        app_login(index * 10, f"leaked{index}@mail.com", f"95.24.{index}.1") for index in range(40)
    )
    assert len(alerts_for(rules, events, "credential_stuffing")) == 1


def test_credential_stuffing_ignores_busy_morning_logins(rules: RuleSet) -> None:
    events = normalized(
        app_login(index * 10, f"user{index}", f"78.160.{index}.1", AuthResult.SUCCESS)
        for index in range(60)
    )
    assert fired(rules, events)["credential_stuffing"] == 0


def test_brute_force_followed_by_success_is_critical(rules: RuleSet) -> None:
    events = [*ssh_failures(12, 5), ssh(70, SshEventKind.ACCEPTED_PASSWORD)]
    alerts = alerts_for(rules, normalized(events), "brute_force_success")
    assert len(alerts) == 1
    assert alerts[0].level == "critical"
    assert alerts[0].has_success
    assert alerts[0].detected_at == events[-1].timestamp


def test_success_before_failures_is_not_brute_force_success(rules: RuleSet) -> None:
    failures = [
        ssh(10 + index * 5, SshEventKind.FAILED_PASSWORD, port=41000 + index) for index in range(12)
    ]
    events = [ssh(0, SshEventKind.ACCEPTED_PASSWORD), *failures]
    assert fired(rules, normalized(events))["brute_force_success"] == 0


def test_typo_then_success_is_not_brute_force_success(rules: RuleSet) -> None:
    events = [*ssh_failures(2, 5), ssh(20, SshEventKind.ACCEPTED_PASSWORD)]
    assert fired(rules, normalized(events))["brute_force_success"] == 0


def test_port_scan_fires_at_twenty_ports(rules: RuleSet) -> None:
    events = normalized(firewall(index * 2, 1000 + index) for index in range(20))
    alerts = alerts_for(rules, events, "port_scan")
    assert len(alerts) == 1
    assert alerts[0].event_count == 20


def test_port_scan_ignores_nineteen_ports_or_slow_probes(rules: RuleSet) -> None:
    few = normalized(firewall(index, 1000 + index) for index in range(19))
    slow = normalized(firewall(index * 30, 1000 + index) for index in range(20))
    assert fired(rules, few)["port_scan"] == 0
    assert fired(rules, slow)["port_scan"] == 0


def test_port_scan_ignores_internal_sources(rules: RuleSet) -> None:
    events = normalized(firewall(index, 1000 + index, "10.20.0.5") for index in range(40))
    assert fired(rules, events)["port_scan"] == 0


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/reports?id=1%27%20OR%20%271%27%3D%271",
        "/search?q=-1 UNION SELECT username,password FROM users--",
        "/download?file=../../../../etc/passwd",
        "/static/..%2f..%2fetc%2fpasswd",
        "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/search?q=\\x22><img src=x onerror=alert(1)>",
    ],
)
def test_web_attack_patterns_are_detected(rules: RuleSet, path: str) -> None:
    assert fired(rules, normalized([request(0, path)]))["web_attack_pattern"] == 1


@pytest.mark.parametrize(
    "path",
    ["/dashboard", "/api/v1/reports?id=12", "/search?q=union+station", "/static/js/app.js"],
)
def test_normal_requests_are_not_web_attacks(rules: RuleSet, path: str) -> None:
    assert fired(rules, normalized([request(0, path)])) == Counter()


def test_scanner_user_agent_is_detected_once_per_source(rules: RuleSet) -> None:
    agent = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
    events = normalized(request(index, "/admin/", agent) for index in range(30))
    alerts = alerts_for(rules, events, "scanner_user_agent")
    assert len(alerts) == 1
    assert alerts[0].event_count == 30


def test_impossible_travel_between_continents(rules: RuleSet) -> None:
    events = normalized(
        [
            app_login(0, "ayse.yilmaz", ISTANBUL_IP, AuthResult.SUCCESS),
            app_login(1800, "ayse.yilmaz", NEW_YORK_IP, AuthResult.SUCCESS),
        ]
    )
    alerts = alerts_for(rules, events, "impossible_travel")
    assert len(alerts) == 1
    assert (alerts[0].entity_type, alerts[0].entity) == ("user", "ayse.yilmaz")
    assert alerts[0].source_ip == NEW_YORK_IP


def test_impossible_travel_ignores_short_or_slow_trips(rules: RuleSet) -> None:
    nearby = normalized(
        [
            app_login(0, "ayse.yilmaz", ISTANBUL_IP, AuthResult.SUCCESS),
            app_login(600, "ayse.yilmaz", ANKARA_IP, AuthResult.SUCCESS),
        ]
    )
    overnight = normalized(
        [
            app_login(0, "ayse.yilmaz", ISTANBUL_IP, AuthResult.SUCCESS),
            app_login(20 * 3600, "ayse.yilmaz", NEW_YORK_IP, AuthResult.SUCCESS),
        ]
    )
    failed = normalized(
        [
            app_login(0, "ayse.yilmaz", ISTANBUL_IP, AuthResult.SUCCESS),
            app_login(600, "ayse.yilmaz", NEW_YORK_IP, AuthResult.FAILURE),
        ]
    )
    for events in (nearby, overnight, failed):
        assert fired(rules, events)["impossible_travel"] == 0


def test_impossible_travel_ignores_domestic_carrier_geolocation(rules: RuleSet) -> None:
    home_munich, mobile_berlin = "79.200.0.10", "79.192.0.10"
    events = normalized(
        [
            app_login(0, "lena.maier", home_munich, AuthResult.SUCCESS),
            app_login(1200, "lena.maier", mobile_berlin, AuthResult.SUCCESS),
        ]
    )
    assert (
        GEO.locate([home_munich])[home_munich].city
        != GEO.locate([mobile_berlin])[mobile_berlin].city
    )
    assert fired(rules, events)["impossible_travel"] == 0


def test_impossible_travel_ignores_same_carrier_across_a_large_country(rules: RuleSet) -> None:
    new_york, san_francisco = "73.0.10.10", "73.32.10.10"
    located = GEO.locate([new_york, san_francisco])
    assert located[new_york].asn == located[san_francisco].asn
    assert located[new_york].city != located[san_francisco].city
    events = normalized(
        [
            app_login(0, "eric.smith", new_york, AuthResult.SUCCESS),
            app_login(600, "eric.smith", san_francisco, AuthResult.SUCCESS),
        ]
    )
    assert fired(rules, events)["impossible_travel"] == 0


def test_detector_boolean_parameters_stay_boolean(rules: RuleSet) -> None:
    parameters = rules.detectors[0].parameters
    assert parameters["ignore_same_asn"] is True
    assert parameters["max_speed_kmh"] == 900


@pytest.mark.parametrize(("scenario", "expected"), sorted(SCENARIO_RULES.items()))
def test_simulated_attack_triggers_its_rules(
    rules: RuleSet, scenario: str, expected: set[str]
) -> None:
    assert expected <= set(fired(rules, scenario_events(scenario)))


def test_normal_workday_raises_no_credential_or_scan_alerts(rules: RuleSet) -> None:
    alerts = fired(rules, scenario_events("", baseline=True))
    noisy = {"impossible_travel"}
    assert {name: count for name, count in alerts.items() if name not in noisy} == {}
