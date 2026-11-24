"""BookMyHost Dev Tools: free single-purpose developer web tools (FastAPI)."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import bgp, dns, health, http_check, lookingglass, mail, pass_, portcheck, rdns, smtp, subnet, whois
from app.api import dnsbl as dnsbl_api
from app.core import config, cooldown, turnstile
from app.core.config import (API_PREFIX, BASE_URL, CALCULATORS, CATEGORIES, CORS_ORIGINS, EMBED_BASE_URL,
                             EMBED_RATE_PER_MIN, RATE_LIMIT_PER_MIN, SITE_NAME, STATIC_PREFIX,
                             RDNS_GUIDE_PUBLISHED, RDNS_GUIDE_URL, TOOLS, TOOLS_HUB_LASTMOD, TOOLS_PREFIX, VERSION)
from app.core.ratelimit import TokenBucket, client_ip
from app.pages import PAGES

ROOT = Path(__file__).resolve().parent
log = logging.getLogger("bmh_tools")
EMBED_PREFIX = f"{TOOLS_PREFIX}/embed/"
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)
    log.propagate = False

app = FastAPI(
    title="BookMyHost Dev Tools API",
    version=VERSION,
    description="Free developer tools by the BookMyHost engineering team: DNS propagation, subnet calculator, TTFB & SSL checker, looking glass, WHOIS/RDAP, reverse DNS, port checker.",
    docs_url=None,  # served below with a nonce'd CSP
    redoc_url=None,
    openapi_url=f"{API_PREFIX}/openapi.json",
    contact={"name": "BookMyHost", "url": "https://bookmyhost.com"},
    license_info={"name": "MIT"},
    servers=[{"url": BASE_URL}],
)
app.add_middleware(
    CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Tools-Pass", "X-Tools-Embed"],
    max_age=600,
)
app.include_router(pass_.router, prefix=API_PREFIX)
app.include_router(dns.router, prefix=API_PREFIX)
app.include_router(subnet.router, prefix=API_PREFIX)
app.include_router(http_check.router, prefix=API_PREFIX)
for _r in (lookingglass.router, whois.router, rdns.router, portcheck.router, mail.router, dnsbl_api.router,
           smtp.router, health.router, bgp.router):
    app.include_router(_r, prefix=API_PREFIX)
app.mount(STATIC_PREFIX, StaticFiles(directory=ROOT / "static"), name="static")

templates = Jinja2Templates(directory=str(ROOT / "templates"))
turnstile.warn_if_disabled()


def _load_glossary() -> dict:
    try:
        return json.loads((ROOT / "data" / "glossary.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("glossary.json missing or invalid")
        return {}


def _json_for_script(obj) -> str:
    """JSON for a <script type="application/json"> block: "</" and "<!--" must never appear raw."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/").replace("<!--", "<\\!--")


GLOSSARY_JSON = _json_for_script(_load_glossary())
TOOLBOX_JSON = _json_for_script({
    "prefix": TOOLS_PREFIX, "api": API_PREFIX,
    "tools": [{k: t[k] for k in ("slug", "name", "category", "icon", "accepts", "heavy")} for t in TOOLS],
})


def _tool_groups() -> list[dict]:
    """Tab-rail groups in CATEGORIES order; empty categories (Email until its tools ship) are hidden."""
    groups = []
    for c in CATEGORIES:
        if c["key"] == "calc":
            items = [{"name": x["name"], "href": x["url"], "icon": x["icon"], "external": True} for x in CALCULATORS]
        else:
            items = [{"name": t["name"], "href": f"{TOOLS_PREFIX}/{t['slug']}", "icon": t["icon"], "slug": t["slug"],
                      "external": False} for t in TOOLS if t["category"] == c["key"]]
        if items:
            groups.append({"key": c["key"], "label": c["label"], "items": items})
    return groups

_static_versions: dict[str, str] = {}


def static_url(rel: str) -> str:
    """Cache-busted static URL: /tools/static/<rel>?v=<sha256-prefix of the file>."""
    v = _static_versions.get(rel)
    if v is None:
        f = ROOT / "static" / rel
        v = hashlib.sha256(f.read_bytes()).hexdigest()[:10] if f.is_file() else VERSION
        _static_versions[rel] = v
    return f"{STATIC_PREFIX}/{rel}?v={v}"


templates.env.globals.update(site_name=SITE_NAME, base_url=BASE_URL, prefix=TOOLS_PREFIX, tools=TOOLS,
                             api=API_PREFIX, static_url=static_url, rate_per_min=RATE_LIMIT_PER_MIN,
                             glossary_json=GLOSSARY_JSON, toolbox_json=TOOLBOX_JSON, tool_groups=_tool_groups(),
                             categories=CATEGORIES, calculators=CALCULATORS, embed_base=EMBED_BASE_URL)

CF = "https://challenges.cloudflare.com"  # Turnstile
PAGE_CSP = ("default-src 'none'; script-src 'self' 'nonce-{nonce}' " + CF + "; style-src 'self'; style-src-attr 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self' " + CF + "; frame-src 'self' " + CF + "; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests")
# Only /tools/embed/* may be framed (by any site); every other path keeps frame-ancestors 'none' + X-Frame-Options DENY.
EMBED_CSP = PAGE_CSP.replace("frame-ancestors 'none'", "frame-ancestors *")
DOCS_CSP = ("default-src 'none'; script-src 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            "style-src https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
API_CSP = "default-src 'none'; frame-ancestors 'none'"


_embed_bucket = TokenBucket(EMBED_RATE_PER_MIN)
_embed_refs: Counter = Counter()  # referrer hostnames only (never IPs)
_embed_flush_at = time.monotonic()
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,98}[a-z0-9])?$")


def clean_host(value: str | None) -> str | None:
    """Referer / X-Tools-Embed value -> bare lowercase hostname, or None if it does not look like one."""
    v = (value or "").strip().lower()
    if "//" in v:
        v = urlparse(v).hostname or ""
    else:
        m = re.fullmatch(r"([^:/]+)(:\d{1,5})?(/.*)?", v)
        v = m[1] if m else ""
    return v if _HOST_RE.match(v) else None


def note_embed_referrer(host: str | None) -> None:
    """Count an embed page view by referrer host; one aggregate log line per hour."""
    global _embed_flush_at
    now = time.monotonic()
    if now - _embed_flush_at >= 3600:
        if _embed_refs:
            log.info("embed referrers (last hour): %s", dict(_embed_refs.most_common(50)))
        _embed_refs.clear()
        _embed_flush_at = now
    if host and (host in _embed_refs or len(_embed_refs) < 500):
        _embed_refs[host] += 1
    elif not host:
        _embed_refs["(none)"] += 1


@app.exception_handler(cooldown.TargetBusy)
async def _target_busy(request: Request, exc: cooldown.TargetBusy):
    return cooldown.busy_response()


@app.exception_handler(turnstile.PassRequired)
async def _pass_required(request: Request, exc: turnstile.PassRequired):
    return turnstile.pass_required_response()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    t0 = time.perf_counter()
    path = request.url.path
    early: Response | None = None
    if path.startswith(API_PREFIX) and request.headers.get("x-tools-embed") is not None:
        # Calls made from an embedded widget: own bucket per IP + embedding site, on top of the normal limits.
        host = clean_host(request.headers.get("x-tools-embed")) or "unknown"
        if not _embed_bucket.allow(f"{client_ip(request)}|{host}"):
            early = JSONResponse({"detail": f"Rate limit exceeded: {EMBED_RATE_PER_MIN} widget requests per minute."},
                                 status_code=429, headers={"Retry-After": "10"})
    try:
        resp: Response = early or await call_next(request)
    except Exception:
        log.exception("unhandled %s %s", request.method, request.url.path)
        raise
    h = resp.headers
    is_embed = path.startswith(EMBED_PREFIX)
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if is_embed:
        if "x-frame-options" in h:
            del h["x-frame-options"]
    else:
        h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if path.startswith(API_PREFIX) or path == f"{TOOLS_PREFIX}/healthz":
        h["X-Robots-Tag"] = "noindex"  # API is not for search engines; pages are.
        h["Cache-Control"] = "no-store"
        if path == f"{API_PREFIX}/docs":
            h["Content-Security-Policy"] = DOCS_CSP.format(nonce=nonce)
        else:
            h["Content-Security-Policy"] = API_CSP
    elif path.startswith(STATIC_PREFIX + "/"):
        h["Cache-Control"] = "public, max-age=2592000, immutable" if request.url.query.startswith("v=") \
            else "public, max-age=86400"
    else:
        h.setdefault("Cache-Control", "no-cache")
        h["Content-Security-Policy"] = (EMBED_CSP if is_embed else PAGE_CSP).format(nonce=nonce)
    # Access log without query strings or bodies (journald / docker logs).
    if not path.startswith(STATIC_PREFIX + "/") and path != f"{TOOLS_PREFIX}/healthz":
        log.info("%s %s %s %.0fms", request.method, path[:200], resp.status_code, (time.perf_counter() - t0) * 1000)
    return resp


def _tool(slug: str) -> dict:
    return next(t for t in TOOLS if t["slug"] == slug)


def _render(request: Request, template: str, slug: str | None, faq: list[tuple[str, str]], **ctx) -> HTMLResponse:
    tool = _tool(slug) if slug else None
    url = f"{BASE_URL}{TOOLS_PREFIX}/{slug}" if slug else f"{BASE_URL}{TOOLS_PREFIX}/"
    schema = [{
        "@context": "https://schema.org", "@type": "FAQPage",
        "mainEntity": [{"@type": "Question", "name": q,
                        "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in faq],
    }]
    if tool:
        schema.append({
            "@context": "https://schema.org", "@type": "SoftwareApplication",
            "name": tool["name"], "url": url, "applicationCategory": "DeveloperApplication",
            "operatingSystem": "Any", "browserRequirements": "Requires JavaScript for live results",
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "INR"},
            "description": tool["short"],
            "author": {"@type": "Organization", "name": "BookMyHost", "url": "https://bookmyhost.com"},
            "publisher": {"@type": "Organization", "name": "Blazing Bullet Pvt Ltd", "url": "https://bookmyhost.com"},
        })
    # "</" must never appear raw inside the JSON-LD <script> block.
    schema_json = json.dumps(schema, ensure_ascii=False).replace("</", "<\\/")
    return templates.TemplateResponse(request, template, {
        "tool": tool, "canonical": url, "faq": faq, "schema_json": schema_json, "layout": "shell.html",
        "embed": False, "noindex": bool(request.query_params.get("q")),
        "turnstile_sitekey": config.TURNSTILE_SITEKEY if turnstile.enabled() else "",
        "tool_url": f"{EMBED_BASE_URL}{TOOLS_PREFIX}/{slug}" if slug else "",
        "csp_nonce": request.state.csp_nonce, **ctx,
    })


@app.get(TOOLS_PREFIX, include_in_schema=False)
async def index_redirect():
    return RedirectResponse(f"{TOOLS_PREFIX}/", status_code=301)


@app.get(f"{TOOLS_PREFIX}/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    faq = [
        ("Are these developer tools free?",
         "Yes. Every tool here is free, needs no sign-up and has a public JSON API. They are built and run by the BookMyHost engineering team."),
        ("Can I link to or embed a tool?",
         "Yes, please do. Each tool page has a ready-made HTML snippet you can paste into docs, blogs or internal wikis."),
    ]
    return _render(request, "index.html", None, faq,
                   title="Free Developer Tools: Email, DNS, BGP, Looking Glass, WHOIS, SSL | BookMyHost",
                   description="Free, fast developer tools from BookMyHost: domain health report, SPF, DKIM and DMARC checkers, blacklist check, DNS and propagation lookups, ASN and BGP prefix lookup, looking glass from Noida and worldwide, WHOIS/RDAP, reverse DNS, ports, subnets, TTFB and SSL.")


@app.get(f"{TOOLS_PREFIX}/dns-propagation-checker", response_class=HTMLResponse, include_in_schema=False)
async def page_dns(request: Request):
    faq = [
        ("How long does DNS propagation take?",
         "Usually minutes to a few hours; worst case up to 48 hours. The limiting factor is the TTL of the old record cached by each resolver. Lower the TTL a day before you plan a change."),
        ("Why do some resolvers show the old value?",
         "They still hold the previous record in cache until its TTL expires. Resolvers that never cached the record return the new value immediately."),
        ("Which resolvers are checked?",
         "18 public resolvers: Google, Cloudflare, Quad9, OpenDNS, Level3, Comodo, CleanBrowsing, AdGuard, Yandex, Hurricane Electric, plus region-labelled anycast nodes for India, Singapore, Germany, Australia, Brazil, Japan and the USA, and the authoritative nameserver of the zone."),
        ("What does propagated X/Y mean?",
         "X of the Y resolvers returned exactly the same record set as the authoritative nameserver. When a resolver disagrees it is shown in amber."),
        ("Is there an API?",
         f"Yes: POST {API_PREFIX}/dns/propagation with JSON {{\"name\": \"example.com\", \"type\": \"A\"}}. Rate limit is {RATE_LIMIT_PER_MIN} requests per minute per IP."),
    ]
    return _render(request, "dns.html", "dns-propagation-checker", faq,
                   title="DNS Propagation Checker (India + 17 global resolvers) | BookMyHost",
                   description="Check DNS propagation of A, AAAA, CNAME, MX, NS, TXT, SOA and PTR records across 18 public resolvers worldwide, including India, against the authoritative nameserver. Free, no sign-up.")


@app.get(f"{TOOLS_PREFIX}/subnet-calculator", response_class=HTMLResponse, include_in_schema=False)
async def page_subnet(request: Request):
    faq = [
        ("How many usable hosts are in a /24?",
         "254. A /24 has 256 addresses; the first is the network address and the last is the broadcast address. A /31 (point-to-point, RFC 3021) and /32 have no such reservation."),
        ("How is IPv6 different?",
         "There is no broadcast address in IPv6. The calculator reserves only the subnet-router anycast address (the all-zeros host) in prefixes shorter than /127."),
        ("What is a wildcard mask?",
         "The bitwise inverse of the subnet mask, used in Cisco ACLs and OSPF network statements. For 255.255.252.0 the wildcard is 0.0.3.255."),
        ("Can I split a network into subnets?",
         "Yes. Enter a CIDR and a new (longer) prefix to list every subnet, up to 1024 at a time, or paste several CIDRs to summarise them into the smallest supernet."),
        ("Does this send my IP ranges to a server?",
         f"Not unless you want to. The calculator runs entirely in your browser; the JSON API (POST {API_PREFIX}/subnet/calc) is optional for scripts and automation."),
    ]
    return _render(request, "subnet.html", "subnet-calculator", faq,
                   title="IPv4 / IPv6 Subnet Calculator (CIDR, split, supernet) | BookMyHost",
                   description="Instant IPv4 and IPv6 subnet calculator: network, broadcast, usable range, hosts, netmask, wildcard, binary, class, reverse DNS zone. Split a CIDR into subnets or summarise many into a supernet. Free JSON API.")


@app.get(f"{TOOLS_PREFIX}/ttfb-ssl-checker", response_class=HTMLResponse, include_in_schema=False)
async def page_ttfb(request: Request):
    faq = [
        ("What is TTFB?",
         "Time To First Byte: the delay between sending the HTTP request and receiving the first byte of the response. It includes server processing time but not DNS, TCP or TLS setup, which are shown separately."),
        ("What is a good TTFB?",
         "Under 200 ms from a nearby location is good; 200 to 500 ms is acceptable; above 800 ms indicates slow origin processing, no caching or a distant server."),
        ("Where is the measurement taken from?",
         "From a BookMyHost server in India. Latency to sites hosted abroad includes the intercontinental round trip, so compare numbers between runs rather than against a global benchmark."),
        ("Why does the SSL check say hostname mismatch?",
         "The certificate does not list the hostname you entered in its Subject Alternative Names. Browsers show a security warning in this case. Reissue the certificate with the correct names."),
        ("Does it check OCSP stapling?",
         "Not yet. It reports TLS version, cipher, certificate subject, issuer, SAN list, validity window, days remaining, chain length, signature algorithm, HSTS header and HTTP/2 support."),
        ("Can it test private or internal addresses?",
         "No. Private, loopback, link-local, CGNAT and other internal addresses are refused, including names that resolve to them and redirects that point to them."),
    ]
    return _render(request, "ttfb.html", "ttfb-ssl-checker", faq,
                   title="TTFB & SSL Certificate Checker (DNS, TCP, TLS waterfall) | BookMyHost",
                   description="Measure DNS lookup, TCP connect, TLS handshake, time to first byte and total load time of any URL, follow redirects and inspect the SSL certificate: issuer, SAN, expiry, TLS version, cipher, HSTS, HTTP/2.")


@app.get(f"{TOOLS_PREFIX}/looking-glass", response_class=HTMLResponse, include_in_schema=False)
async def page_lg(request: Request):
    faq = [
        ("Where do the ping and traceroute run from?",
         "By default from a BookMyHost server in Noida, India, on our own network (AS152523). The From menu also runs the test from up to six probes in India, Asia, Europe, North America or worldwide, using the public Globalping network, so you can compare latency by location. Traceroute hops show the network (AS) and an approximate location from public routing data."),
        ("What is the BGP lookup based on?",
         "Public BGP data from RIPEstat (RIPE NCC route collectors): the announced prefix, the origin AS and sample AS paths. We do not query our own routers for this."),
        ("What are the limits?",
         "Ping sends 4 packets, traceroute stops after 30 hops, each run is time-limited, and each IP may start a few runs per minute, one at a time. Only public IPv4/IPv6 addresses and hostnames that resolve to public addresses are accepted."),
        ("Why are some traceroute hops shown as stars?",
         "Many routers do not answer or rate-limit TTL-expired probes. A star in the middle of a path is normal as long as later hops answer."),
        ("Is there an API?",
         f"Yes: POST {API_PREFIX}/lg/run with JSON {{\"target\": \"1.1.1.1\", \"tool\": \"ping\"}} and POST {API_PREFIX}/lg/bgp with {{\"target\": \"8.8.8.8\"}}."),
    ]
    return _render(request, "lg.html", "looking-glass", faq,
                   title="Looking Glass: Ping, Traceroute & BGP from India (AS152523) | BookMyHost",
                   description="Free looking glass from Noida, India (AS152523): run ping and traceroute to any public IP or hostname and look up the BGP prefix, origin AS and AS paths. No sign-up.")


@app.get(f"{TOOLS_PREFIX}/whois-lookup", response_class=HTMLResponse, include_in_schema=False)
async def page_whois(request: Request):
    faq = [
        ("What is the difference between WHOIS and RDAP?",
         "RDAP is the modern, JSON-based replacement for the WHOIS protocol. It is standardised, supports HTTPS and returns structured data. This tool uses RDAP and only falls back to classic WHOIS for a TLD that has no RDAP service."),
        ("Why is the registrant hidden?",
         "Since GDPR most registries and registrars redact personal data. We never display personal contact details; you see the registrar, dates, status and nameservers."),
        ("Can I look up an IP address?",
         "Yes. Enter an IPv4 or IPv6 address and we query the regional internet registry (ARIN, RIPE, APNIC, LACNIC or AFRINIC) for the network name, range, country and abuse role."),
        ("How current is the data?",
         "Answers come live from the registry and are cached for 5 minutes."),
    ]
    return _render(request, "whois.html", "whois-lookup", faq,
                   title="WHOIS & RDAP Lookup for Domains and IP Addresses | BookMyHost",
                   description="Free WHOIS / RDAP lookup: registrar, creation and expiry dates, status and nameservers of any domain, or network owner, range and country of any IPv4/IPv6 address.")


@app.get(f"{TOOLS_PREFIX}/reverse-dns-lookup", response_class=HTMLResponse, include_in_schema=False)
async def page_rdns(request: Request):
    faq = [
        ("What is a PTR record?",
         "A PTR record maps an IP address back to a hostname (the reverse of an A or AAAA record). It lives in the in-addr.arpa (IPv4) or ip6.arpa (IPv6) zone, controlled by the owner of the IP block."),
        ("What is forward-confirmed reverse DNS (FCrDNS)?",
         "The PTR hostname must resolve (A or AAAA) back to the same IP address. Mail servers use it as a basic proof that the sender controls both sides."),
        ("Why does my mail go to spam without a PTR record?",
         "Large mailbox providers expect a valid, matching PTR on the sending IP. A missing or generic one (for example 203-0-113-9.isp.example) is a common reason for rejection."),
        ("How do I set a PTR record on a VPS?",
         "The reverse zone belongs to your provider, so set it in the server control panel or ask support. Use the same hostname as your mail server's HELO name and make sure its A record points to the IP."),
    ]
    return _render(request, "rdns.html", "reverse-dns-lookup", faq, guide_url=RDNS_GUIDE_URL if RDNS_GUIDE_PUBLISHED else None,
                   title="Reverse DNS (PTR) Lookup with FCrDNS Check | BookMyHost",
                   description="Free reverse DNS lookup for IPv4 and IPv6: see the PTR record and check forward-confirmed reverse DNS (FCrDNS), which mail servers rely on for delivery.")


@app.get(f"{TOOLS_PREFIX}/port-checker", response_class=HTMLResponse, include_in_schema=False)
async def page_ports(request: Request):
    faq = [
        ("Which IP address is checked?",
         "Only your own public IP address, as seen by our server when you open the page. You cannot enter another address, so the tool cannot be used to scan other people's systems."),
        ("What do open, closed and filtered mean?",
         "Open: something accepted the TCP connection. Closed: the host answered that nothing listens there. Filtered: no answer within 3 seconds, usually a firewall dropping the traffic."),
        ("Why does a port I opened show as closed or filtered?",
         "Check that the service is running and listening on a public address, and that the server firewall, the cloud security group and your router (port forwarding) all allow the port. Behind CGNAT or a VPN the visible IP is not your machine."),
        ("Is it free and are there limits?",
         "Yes. A few checks per minute per IP, one port or the common-port set, 3 second timeout per port."),
    ]
    return _render(request, "ports.html", "port-checker", faq,
                   title="Open Port Checker: Is My Port Open? (Your IP) | BookMyHost",
                   description="Free open port checker: test whether common TCP ports (22, 80, 443, 3306, 3389 and more) or any port 1-65535 are reachable on your own public IP address.")


def _make_page(slug: str):
    async def handler(request: Request):
        p = PAGES[slug]
        return _render(request, "tool_generic.html", slug, p["faq"], title=p["title"], description=p["description"], page=p)
    handler.__name__ = "page_" + slug.replace("-", "_")
    return handler


for _slug in PAGES:  # email / DNS / BGP suite: one generic template, one JS module per slug
    app.get(f"{TOOLS_PREFIX}/{_slug}", response_class=HTMLResponse, include_in_schema=False)(_make_page(_slug))

_ACCENT_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_EMBED_TEMPLATES = {
    "dns-propagation-checker": "dns.html", "subnet-calculator": "subnet.html", "ttfb-ssl-checker": "ttfb.html",
    "looking-glass": "lg.html", "whois-lookup": "whois.html", "reverse-dns-lookup": "rdns.html",
    "port-checker": "ports.html", **{s: "tool_generic.html" for s in PAGES}}


@app.get(f"{TOOLS_PREFIX}/embed/{{slug}}", response_class=HTMLResponse, include_in_schema=False)
async def embed_page(request: Request, slug: str, theme: str = "auto", accent: str | None = None,
                     q: str | None = None, compact: str | None = None):
    """Minimal-chrome tool for iframes. Frameable by any site (see security_headers); never indexed."""
    tool = next((t for t in TOOLS if t["slug"] == slug and t.get("embeddable")), None)
    if tool is None or slug not in _EMBED_TEMPLATES:
        raise HTTPException(status_code=404, detail="Unknown or non-embeddable tool.")
    theme = theme if theme in ("light", "dark", "auto") else "auto"
    accent = accent if accent and _ACCENT_RE.match(accent) else None
    host = clean_host(request.headers.get("referer"))
    note_embed_referrer(host)
    tool_url = f"{EMBED_BASE_URL}{TOOLS_PREFIX}/{slug}"
    return templates.TemplateResponse(request, _EMBED_TEMPLATES[slug], {
        "tool": tool, "canonical": f"{BASE_URL}{TOOLS_PREFIX}/{slug}", "faq": [], "layout": "embed.html", "embed": True,
        "title": f"{tool['name']} | BookMyHost", "description": tool["short"], "schema_json": "[]",
        "noindex": True, "page": PAGES.get(slug), "theme": theme, "accent": accent, "compact": compact == "1", "embed_host": host or "",
        "powered_href": f"{tool_url}?utm_source={host or 'embed'}&utm_medium=widget&utm_campaign=tools-embed",
        "turnstile_sitekey": config.TURNSTILE_SITEKEY if turnstile.enabled() else "", "tool_url": tool_url,
        "guide_url": RDNS_GUIDE_URL if RDNS_GUIDE_PUBLISHED else None, "csp_nonce": request.state.csp_nonce,
    })


@app.get(f"{TOOLS_PREFIX}/embed.js", include_in_schema=False)
async def embed_js():
    return FileResponse(ROOT / "static" / "embed.js", media_type="application/javascript",
                        headers={"Cache-Control": "public, max-age=3600"})


@app.get(f"{API_PREFIX}/docs", include_in_schema=False)
async def api_docs(request: Request):
    html = get_swagger_ui_html(openapi_url=app.openapi_url, title="BookMyHost Dev Tools API").body.decode()
    nonce = request.state.csp_nonce
    html = html.replace("<script>", f'<script nonce="{nonce}">').replace("<script src=", f'<script nonce="{nonce}" src=')
    return HTMLResponse(html)


@app.get(f"{TOOLS_PREFIX}/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "version": VERSION}


@app.get(f"{TOOLS_PREFIX}/sitemap.xml", include_in_schema=False)
async def sitemap():
    urls = [(f"{BASE_URL}{TOOLS_PREFIX}/", TOOLS_HUB_LASTMOD)] + [
        (f"{BASE_URL}{TOOLS_PREFIX}/{t['slug']}", t["lastmod"]) for t in TOOLS]
    body = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    body += "".join(f"  <url><loc>{u}</loc><lastmod>{d}</lastmod><changefreq>monthly</changefreq></url>\n" for u, d in urls)
    body += "</urlset>\n"
    return Response(body, media_type="application/xml", headers={"Cache-Control": "public, max-age=3600"})
