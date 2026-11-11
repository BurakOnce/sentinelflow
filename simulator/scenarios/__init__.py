from simulator.scenarios.account_compromise import impossible_travel
from simulator.scenarios.base import AttackStep, Scenario, ScenarioContext
from simulator.scenarios.brute_force import brute_force_success, ssh_bruteforce
from simulator.scenarios.credential_abuse import credential_stuffing, password_spraying
from simulator.scenarios.reconnaissance import port_scan, web_attack

SCENARIOS: dict[str, Scenario] = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "ssh_bruteforce",
            "Single source guessing passwords for one SSH account",
            ("T1110.001",),
            ssh_bruteforce,
        ),
        Scenario(
            "password_spraying",
            "Few sources trying one or two passwords against many portal accounts",
            ("T1110.003", "T1078"),
            password_spraying,
        ),
        Scenario(
            "credential_stuffing",
            "Many proxy sources replaying leaked credentials with varied user agents",
            ("T1110.004", "T1078"),
            credential_stuffing,
        ),
        Scenario(
            "brute_force_success",
            "SSH password guessing that ends with a successful login",
            ("T1110.001", "T1078"),
            brute_force_success,
        ),
        Scenario(
            "port_scan",
            "Single source probing many ports on a public address",
            ("T1046",),
            port_scan,
        ),
        Scenario(
            "web_attack",
            "Scanner probes, SQL injection, path traversal and XSS against the portal",
            ("T1595.002", "T1190"),
            web_attack,
        ),
        Scenario(
            "impossible_travel",
            "Successful logins for one account from distant countries within minutes",
            ("T1078",),
            impossible_travel,
        ),
    )
}

__all__ = ["SCENARIOS", "AttackStep", "Scenario", "ScenarioContext"]
