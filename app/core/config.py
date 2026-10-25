"""Runtime configuration (env-driven, sane defaults)."""
import os

SITE_NAME = "BookMyHost Dev Tools"
BASE_URL = os.getenv("BMH_TOOLS_BASE_URL", "https://bookmyhost.com").rstrip("/")
TOOLS_PREFIX = os.getenv("BMH_TOOLS_PREFIX", "/tools").rstrip("/")  # public path prefix
CORS_ORIGINS = [o for o in os.getenv(
    "BMH_TOOLS_CORS", "https://bookmyhost.com,https://www.bookmyhost.com,https://my.bookmyhost.com"
).split(",") if o]
RATE_LIMIT_PER_MIN = int(os.getenv("BMH_TOOLS_RATE_PER_MIN", "30"))
DNS_TIMEOUT = float(os.getenv("BMH_TOOLS_DNS_TIMEOUT", "2.0"))
HTTP_TIMEOUT = float(os.getenv("BMH_TOOLS_HTTP_TIMEOUT", "10.0"))
MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MiB cap
ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_REDIRECTS = 5
MAX_SPLIT_SUBNETS = 1024

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
