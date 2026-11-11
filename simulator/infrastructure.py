from typing import Final

PORTAL_IP: Final = "203.0.113.10"
BASTION_IP: Final = "203.0.113.22"
BASTION_INTERNAL_IP: Final = "10.20.0.10"
FIREWALL_HOST: Final = "fw-edge-01"
BASTION_HOST: Final = "bastion-01"
INTERNAL_SSH_HOSTS: Final = ("app-01", "app-02", "db-01", "worker-01")
PUBLIC_ADDRESSES: Final = (PORTAL_IP, BASTION_IP)
OPEN_PORTS: Final = {PORTAL_IP: (80, 443), BASTION_IP: (22,)}
EXISTING_SYSTEM_ACCOUNTS: Final = ("root", "deploy")
NONEXISTENT_ACCOUNTS: Final = ("admin", "ubuntu", "git", "postgres", "oracle", "test", "user")

DESKTOP_USER_AGENTS: Final = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/26.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
)

MOBILE_USER_AGENTS: Final = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Mobile Safari/537.36",
)

CRAWLER_USER_AGENTS: Final = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
)

SCRIPT_USER_AGENTS: Final = (
    "python-requests/2.32.3",
    "curl/8.5.0",
    "Go-http-client/1.1",
)

SQLMAP_USER_AGENT: Final = "sqlmap/1.9.8#stable (https://sqlmap.org)"
NIKTO_USER_AGENT: Final = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:{test_id:06d})"
