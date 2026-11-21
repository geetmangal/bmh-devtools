"""Runtime configuration (env-driven, sane defaults)."""
import os

SITE_NAME = "BookMyHost Dev Tools"
VERSION = "1.2.0"
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

# --- network tools (looking glass, WHOIS/RDAP, reverse DNS, port checker) ---
# Looking glass: runs from this server (Noida, AS152523). Strict own limits on top of the global one.
LG_ASN = "AS152523"
LG_LOCATION = "Noida, India"
LG_RATE_PER_MIN = int(os.getenv("BMH_TOOLS_LG_RATE_PER_MIN", "6"))   # per IP, burst 3
LG_BURST = int(os.getenv("BMH_TOOLS_LG_BURST", "3"))
MAX_CONCURRENT_LG = int(os.getenv("BMH_TOOLS_MAX_LG", "3"))          # global concurrent ping/traceroute runs
LG_PING_COUNT = 4                                                    # hard cap, not configurable
LG_TRACE_MAX_HOPS = 30                                               # hard cap, not configurable
LG_PING_TIMEOUT = 12.0                                               # whole-command wall clock (s)
LG_TRACE_TIMEOUT = 40.0
RIPESTAT_URL = os.getenv("BMH_TOOLS_RIPESTAT_URL", "https://stat.ripe.net/data").rstrip("/")
RIPESTAT_TIMEOUT = float(os.getenv("BMH_TOOLS_RIPESTAT_TIMEOUT", "8.0"))
RDAP_TIMEOUT = float(os.getenv("BMH_TOOLS_RDAP_TIMEOUT", "8.0"))
RDAP_BOOTSTRAP_URL = os.getenv("BMH_TOOLS_RDAP_BOOTSTRAP", "https://data.iana.org/rdap")
MAX_CONCURRENT_NET = int(os.getenv("BMH_TOOLS_MAX_NET", "6"))        # whois / rdns / bgp / port checks
NET_RATE_PER_MIN = int(os.getenv("BMH_TOOLS_NET_RATE_PER_MIN", "20"))  # whois + rdns per IP
PORT_RATE_PER_MIN = int(os.getenv("BMH_TOOLS_PORT_RATE_PER_MIN", "8"))  # port checker per IP, burst 4
PORT_TIMEOUT = 3.0
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
# Show the link to the rDNS/PTR guide only once the blog post is live (BMH_TOOLS_RDNS_GUIDE_PUBLISHED=1).
RDNS_GUIDE_PUBLISHED = os.getenv("BMH_TOOLS_RDNS_GUIDE_PUBLISHED", "0").strip().lower() in ("1", "true", "yes", "on")
RDNS_GUIDE_URL = "https://bookmyhost.com/blog/rdns-ptr-record-vps"

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
    {
        "slug": "looking-glass",
        "name": "Looking Glass (Ping, Traceroute, BGP)",
        "short": "Ping, traceroute and BGP route lookup from our Noida network, AS152523.",
    },
    {
        "slug": "whois-lookup",
        "name": "WHOIS / RDAP Lookup",
        "short": "Domain and IP registration data via RDAP: registrar, dates, nameservers, network owner.",
    },
    {
        "slug": "reverse-dns-lookup",
        "name": "Reverse DNS (PTR) Lookup",
        "short": "PTR record for any IPv4 or IPv6 address with a forward-confirmed reverse DNS check.",
    },
    {
        "slug": "port-checker",
        "name": "Open Port Checker",
        "short": "Check which TCP ports are open on your own public IP address.",
    },
]
