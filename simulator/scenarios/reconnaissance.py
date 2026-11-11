from datetime import datetime
from random import Random
from urllib.parse import quote

from simulator.activity import firewall_packet, seconds
from simulator.events import FirewallAction, HttpRequest
from simulator.geo import COUNTRIES, HOSTILE_COUNTRIES
from simulator.infrastructure import (
    NIKTO_USER_AGENT,
    OPEN_PORTS,
    PUBLIC_ADDRESSES,
    SQLMAP_USER_AGENT,
)
from simulator.scenarios.base import AttackStep, ScenarioContext, scaled

NETWORK_SERVICE_DISCOVERY = "T1046"
VULNERABILITY_SCANNING = "T1595.002"
EXPLOIT_PUBLIC_APPLICATION = "T1190"

SCANNER_PROBES = (
    "/.git/config",
    "/.env",
    "/admin/",
    "/phpmyadmin/",
    "/wp-login.php",
    "/server-status",
    "/backup.zip",
    "/config.php.bak",
    "/cgi-bin/test.cgi",
    "/.svn/entries",
    "/web.config",
    "/actuator/env",
    "/manager/html",
    "/.DS_Store",
)
SQL_INJECTION_PAYLOADS = (
    "1' OR '1'='1",
    "1' AND 1=1-- -",
    "1 AND SLEEP(5)",
    "1 UNION ALL SELECT NULL,NULL,CONCAT(0x71766a7071,0x4a,0x7178787a71)-- -",
    "1) AND (SELECT 2961 FROM (SELECT(SLEEP(5)))a)-- -",
    "1';DROP TABLE users;--",
    "-1 UNION SELECT username,password FROM users--",
)
SQL_INJECTION_TARGETS = ("/api/v1/reports?id=", "/api/v1/tickets?status=open&sort=", "/search?q=")
PATH_TRAVERSAL_PATHS = (
    "/static/..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/download?file=../../../../etc/passwd",
    "/download?file=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
    "/api/v1/files?path=....//....//....//etc/hosts",
)
XSS_PAYLOADS = (
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(document.cookie)>',
    "<svg/onload=alert(1)>",
    "javascript:alert(String.fromCharCode(88,83,83))",
)


def _hostile_ip(rng: Random) -> str:
    return COUNTRIES[rng.choice(HOSTILE_COUNTRIES)].random_ip(rng)


def port_scan(
    context: ScenarioContext, rng: Random, start: datetime, intensity: float
) -> list[AttackStep]:
    attacker_ip = _hostile_ip(rng)
    target = rng.choice(PUBLIC_ADDRESSES)
    ports = rng.sample(range(1, 65_536), scaled(1000, intensity, minimum=50))
    now = start
    result: list[AttackStep] = []
    for port in ports:
        open_port = port in OPEN_PORTS[target]
        action = FirewallAction.ACCEPT if open_port else FirewallAction.DROP
        packet = firewall_packet(rng, now, attacker_ip, target, port, action)
        result.append(AttackStep(packet, NETWORK_SERVICE_DISCOVERY, "probe"))
        now += seconds(rng.uniform(0.005, 0.03))
    return result


def _request(
    rng: Random, start: datetime, attacker_ip: str, path: str, status: int, agent: str
) -> HttpRequest:
    return HttpRequest(
        timestamp=start,
        src_ip=attacker_ip,
        method="GET",
        path=path,
        status=status,
        bytes_sent=rng.randint(150, 600) if status != 200 else rng.randint(900, 4_000),
        user_agent=agent,
    )


def web_attack(
    context: ScenarioContext, rng: Random, start: datetime, intensity: float
) -> list[AttackStep]:
    attacker_ip = _hostile_ip(rng)
    now = start
    result: list[AttackStep] = []

    def add(path: str, status: int, agent: str, technique: str, stage: str) -> None:
        nonlocal now
        result.append(
            AttackStep(_request(rng, now, attacker_ip, path, status, agent), technique, stage)
        )
        now += seconds(rng.uniform(0.05, 0.6))

    for test_id in range(scaled(80, intensity, minimum=10)):
        agent = NIKTO_USER_AGENT.format(test_id=test_id + 1)
        status = rng.choices((404, 403, 200), (85, 12, 3))[0]
        add(rng.choice(SCANNER_PROBES), status, agent, VULNERABILITY_SCANNING, "scan")
    for _ in range(scaled(120, intensity, minimum=10)):
        payload = quote(rng.choice(SQL_INJECTION_PAYLOADS), safe="")
        status = rng.choices((200, 500, 403), (50, 35, 15))[0]
        path = f"{rng.choice(SQL_INJECTION_TARGETS)}{payload}"
        add(path, status, SQLMAP_USER_AGENT, EXPLOIT_PUBLIC_APPLICATION, "sql_injection")
    for test_id in range(scaled(25, intensity, minimum=5)):
        agent = NIKTO_USER_AGENT.format(test_id=5000 + test_id)
        status = rng.choice((400, 403, 404))
        path = rng.choice(PATH_TRAVERSAL_PATHS)
        add(path, status, agent, EXPLOIT_PUBLIC_APPLICATION, "path_traversal")
    for test_id in range(scaled(25, intensity, minimum=5)):
        agent = NIKTO_USER_AGENT.format(test_id=7000 + test_id)
        payload = rng.choice(XSS_PAYLOADS)
        encoded = quote(payload, safe="") if rng.random() < 0.6 else payload
        add(
            f"/search?q={encoded}", rng.choice((200, 400)), agent, EXPLOIT_PUBLIC_APPLICATION, "xss"
        )
    return result
