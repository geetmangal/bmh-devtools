"""Runtime configuration (env-driven, sane defaults)."""
import os

SITE_NAME = "BookMyHost Dev Tools"
VERSION = "1.1.0"
BASE_URL = os.getenv("BMH_TOOLS_BASE_URL", "https://bookmyhost.com").rstrip("/")
TOOLS_PREFIX = os.getenv("BMH_TOOLS_PREFIX", "/tools").rstrip("/")  # public path prefix
# Everything (pages, static, JSON API, health) lives under TOOLS_PREFIX so the host site's own
# /api/... routes are never shadowed.
API_PREFIX = f"{TOOLS_PREFIX}/api/v1"
STATIC_PREFIX = f"{TOOLS_PREFIX}/static"
CORS_ORIGINS = [o for o in os.getenv(
    "BMH_TOOLS_CORS", "https://bookmyhost.com,https://www.bookmyhost.com,https://my.bookmyhost.com"
).split(",") if o]
RATE_LIMIT_PER_MIN = int(os.getenv("BMH_TOOLS_RATE_PER_MIN", "30"))
DNS_TIMEOUT = float(os.getenv("BMH_TOOLS_DNS_TIMEOUT", "2.0"))
HTTP_TIMEOUT = float(os.getenv("BMH_TOOLS_HTTP_TIMEOUT", "10.0"))
# Concurrency caps (per process): checks beyond this wait up to QUEUE_WAIT seconds, then 503.
MAX_CONCURRENT_DNS = int(os.getenv("BMH_TOOLS_MAX_DNS", "6"))
MAX_CONCURRENT_HTTP = int(os.getenv("BMH_TOOLS_MAX_HTTP", "4"))
QUEUE_WAIT = float(os.getenv("BMH_TOOLS_QUEUE_WAIT", "5"))
MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MiB cap
ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_REDIRECTS = 5
MAX_SPLIT_SUBNETS = 1024

# SSRF: networks the checkers must never connect to, on top of every non-global range.
# Defaults = the hosting network of the production box (public-direct 160.22.109.0/24):
# gateway .1, this host .2 and the CloudStack virtual router .9 (serves VM userdata/metadata).
# Extend with BMH_TOOLS_BLOCK_NETS (comma list of CIDRs) when the host moves.
ALWAYS_BLOCKED_NETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32",
    "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
]
BLOCKED_NETS = ALWAYS_BLOCKED_NETS + [n.strip() for n in os.getenv(
    "BMH_TOOLS_BLOCK_NETS", "160.22.109.1/32,160.22.109.2/32,160.22.109.9/32"
).split(",") if n.strip()]

TOOLS = [
    {
        "slug": "dns-propagation-checker",
        "name": "DNS Propagation Checker",
        "short": "Check whether your DNS record has propagated to public resolvers worldwide, including India.",
    },
    {
        "slug": "subnet-calculator",
        "name": "IPv4 / IPv6 Subnet Calculator",
        "short": "CIDR calculator with network, broadcast, usable range, wildcard, binary, split and supernet.",
    },
    {
        "slug": "ttfb-ssl-checker",
        "name": "TTFB & SSL Checker",
        "short": "Measure DNS, TCP, TLS, time to first byte and inspect the SSL certificate of any site.",
    },
]
