"""BookMyHost Dev Tools: free single-purpose developer web tools (FastAPI)."""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import dns, http_check, subnet
from app.core.config import (API_PREFIX, BASE_URL, CORS_ORIGINS, RATE_LIMIT_PER_MIN, SITE_NAME, STATIC_PREFIX,
                             TOOLS, TOOLS_PREFIX, VERSION)

ROOT = Path(__file__).resolve().parent
log = logging.getLogger("bmh_tools")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)
    log.propagate = False

app = FastAPI(
    title="BookMyHost Dev Tools API",
    version=VERSION,
    description="Free developer tools by the BookMyHost engineering team: DNS propagation, subnet calculator, TTFB & SSL checker.",
    docs_url=None,  # served below with a nonce'd CSP
    redoc_url=None,
    openapi_url=f"{API_PREFIX}/openapi.json",
    contact={"name": "BookMyHost", "url": "https://bookmyhost.com"},
    license_info={"name": "MIT"},
    servers=[{"url": BASE_URL}],
)
app.add_middleware(
    CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["GET", "POST"], allow_headers=["Content-Type"],
    max_age=600,
)
app.include_router(dns.router, prefix=API_PREFIX)
app.include_router(subnet.router, prefix=API_PREFIX)
app.include_router(http_check.router, prefix=API_PREFIX)
app.mount(STATIC_PREFIX, StaticFiles(directory=ROOT / "static"), name="static")

templates = Jinja2Templates(directory=str(ROOT / "templates"))

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
                             api=API_PREFIX, static_url=static_url, rate_per_min=RATE_LIMIT_PER_MIN)

PAGE_CSP = ("default-src 'none'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; style-src-attr 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
            "frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests")
DOCS_CSP = ("default-src 'none'; script-src 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            "style-src https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
API_CSP = "default-src 'none'; frame-ancestors 'none'"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    t0 = time.perf_counter()
    try:
        resp: Response = await call_next(request)
    except Exception:
        log.exception("unhandled %s %s", request.method, request.url.path)
        raise
    path = request.url.path
    h = resp.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
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
        h["Content-Security-Policy"] = PAGE_CSP.format(nonce=nonce)
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
        "tool": tool, "canonical": url, "faq": faq, "schema_json": schema_json,
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
                   title="Free Developer Tools: DNS, Subnet, TTFB & SSL | BookMyHost",
                   description="Free, fast developer tools from BookMyHost: DNS propagation checker with Indian resolvers, IPv4/IPv6 subnet calculator, TTFB and SSL certificate checker.")


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
    urls = [f"{BASE_URL}{TOOLS_PREFIX}/"] + [f"{BASE_URL}{TOOLS_PREFIX}/{t['slug']}" for t in TOOLS]
    body = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    body += "".join(f"  <url><loc>{u}</loc><changefreq>monthly</changefreq></url>\n" for u in urls)
    body += "</urlset>\n"
    return Response(body, media_type="application/xml", headers={"Cache-Control": "public, max-age=3600"})
