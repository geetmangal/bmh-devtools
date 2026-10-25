"""BookMyHost Dev Tools: free single-purpose developer web tools (FastAPI)."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import dns, http_check, subnet
from app.core.config import BASE_URL, CORS_ORIGINS, SITE_NAME, TOOLS, TOOLS_PREFIX

ROOT = Path(__file__).resolve().parent

app = FastAPI(
    title="BookMyHost Dev Tools API",
    version="1.0.0",
    description="Free developer tools by the BookMyHost engineering team: DNS propagation, subnet calculator, TTFB & SSL checker.",
    docs_url="/api/v1/docs",
    redoc_url=None,
    openapi_url="/api/v1/openapi.json",
    contact={"name": "BookMyHost", "url": "https://bookmyhost.com"},
    license_info={"name": "MIT"},
)
app.add_middleware(
    CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["GET", "POST"], allow_headers=["Content-Type"],
    max_age=600,
)
app.include_router(dns.router, prefix="/api/v1")
app.include_router(subnet.router, prefix="/api/v1")
app.include_router(http_check.router, prefix="/api/v1")
app.mount(f"{TOOLS_PREFIX}/static", StaticFiles(directory=ROOT / "static"), name="static")

templates = Jinja2Templates(directory=str(ROOT / "templates"))
templates.env.globals.update(site_name=SITE_NAME, base_url=BASE_URL, prefix=TOOLS_PREFIX, tools=TOOLS)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.url.path.startswith("/api/"):
        resp.headers["X-Robots-Tag"] = "noindex"  # API is not for search engines; pages are.
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
    return templates.TemplateResponse(request, template, {
        "tool": tool, "canonical": url, "faq": faq, "schema_json": json.dumps(schema, ensure_ascii=False), **ctx,
    })


@app.get(f"{TOOLS_PREFIX}/", response_class=HTMLResponse, include_in_schema=False)
@app.get(TOOLS_PREFIX or "/", response_class=HTMLResponse, include_in_schema=False)
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
         "Yes: POST /api/v1/dns/propagation with JSON {\"name\": \"example.com\", \"type\": \"A\"}. Rate limit is 30 requests per minute per IP."),
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
         "Not unless you want to. The calculator runs entirely in your browser; the JSON API (POST /api/v1/subnet/calc) is optional for scripts and automation."),
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
    ]
    return _render(request, "ttfb.html", "ttfb-ssl-checker", faq,
                   title="TTFB & SSL Certificate Checker (DNS, TCP, TLS waterfall) | BookMyHost",
                   description="Measure DNS lookup, TCP connect, TLS handshake, time to first byte and total load time of any URL, follow redirects and inspect the SSL certificate: issuer, SAN, expiry, TLS version, cipher, HSTS, HTTP/2.")


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok"}


@app.get("/robots.txt", include_in_schema=False)
@app.get(f"{TOOLS_PREFIX}/robots.txt", include_in_schema=False)
async def robots():
    body = f"User-agent: *\nAllow: {TOOLS_PREFIX}/\nDisallow: /api/\nSitemap: {BASE_URL}{TOOLS_PREFIX}/sitemap.xml\n"
    return PlainTextResponse(body)


@app.get(f"{TOOLS_PREFIX}/sitemap.xml", include_in_schema=False)
async def sitemap():
    urls = [f"{BASE_URL}{TOOLS_PREFIX}/"] + [f"{BASE_URL}{TOOLS_PREFIX}/{t['slug']}" for t in TOOLS]
    body = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    body += "".join(f"  <url><loc>{u}</loc><changefreq>monthly</changefreq></url>\n" for u in urls)
    body += "</urlset>\n"
    return Response(body, media_type="application/xml")
