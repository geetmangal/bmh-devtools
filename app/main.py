"""BookMyHost Dev Tools: free single-purpose developer web tools (FastAPI)."""
from __future__ import annotations

import hashlib
import json
import logging
import os
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

from app import content as content_mod
from app import llms
from app.api import bgp, dns, health, http_check, lookingglass, mail, pass_, portcheck, rdns, smtp, subnet, whois
from app.api import dnsbl as dnsbl_api
from app.core import config, cooldown, turnstile
from app.core.config import (API_PREFIX, BASE_URL, CALCULATORS, CATEGORIES, EMAIL_GROUPS, QUICK_STARTS, CORS_ORIGINS, EMBED_BASE_URL,
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


def _compute_build() -> str:
    """Build id used as the versioned static path segment: BMH_TOOLS_BUILD (e.g. the git sha) if set, else a
    content hash of the whole static tree, computed once at startup."""
    env = re.sub(r"[^A-Za-z0-9._-]", "", os.getenv("BMH_TOOLS_BUILD", ""))[:40]
    if env and env.strip(".") != "":
        return env
    base = ROOT / "static"
    digest = hashlib.sha256()
    for f in sorted(p for p in base.rglob("*") if p.is_file()):
        digest.update(f.relative_to(base).as_posix().encode() + b"\0")
        digest.update(f.read_bytes())
    return digest.hexdigest()[:12]


BUILD = _compute_build()
VERSIONED_PREFIX = f"{STATIC_PREFIX}/v/{BUILD}"  # every module, stylesheet and image is served from here, immutable
# Mount order matters: the versioned mount must be tried before the plain /tools/static mount (which still serves the
# same files unversioned, with a short cache, for old bookmarks and for crawlers that fetch OG images).
app.mount(VERSIONED_PREFIX, StaticFiles(directory=ROOT / "static"), name="static_versioned")
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
_CAT_LABELS = {c["key"]: c["label"] for c in CATEGORIES}
TOOLBOX_JSON = _json_for_script({
    "prefix": TOOLS_PREFIX, "api": API_PREFIX,
    "tools": [{**{k: t[k] for k in ("slug", "name", "short", "category", "icon", "accepts", "heavy")},
               "category_label": _CAT_LABELS.get(t["category"], t["category"]),
               "group": t.get("group", ""), "badge": t.get("badge", ""),
               "keywords": t.get("keywords", []), "client_only": bool(t.get("client_only", False))}
              for t in TOOLS],
})


def _tool_groups() -> list[dict]:
    """Tab-rail groups in CATEGORIES order; empty categories are hidden. Email also carries `subgroups`."""
    groups = []
    for c in CATEGORIES:
        if c["key"] == "calc":
            items = [{"name": x["name"], "href": x["url"], "icon": x["icon"], "external": True} for x in CALCULATORS]
        else:
            items = [{"name": t["name"], "href": f"{TOOLS_PREFIX}/{t['slug']}", "icon": t["icon"], "slug": t["slug"],
                      "external": False, "group": t.get("group", ""), "badge": t.get("badge", "")}
                     for t in TOOLS if t["category"] == c["key"]]
        if items:
            g = {"key": c["key"], "label": c["label"], "items": items, "count": len(items)}
            if c["key"] == "email":
                g["subgroups"] = [{"key": k, "label": lbl, "tools": [i for i in items if i["group"] == k]}
                                  for k, lbl in EMAIL_GROUPS]
            groups.append(g)
    return groups


def _category_siblings(slug: str) -> list[dict]:
    """Tools in the same category as `slug` (including itself), in TOOLS order."""
    cat = next((t["category"] for t in TOOLS if t["slug"] == slug), None)
    return [t for t in TOOLS if t["category"] == cat] if cat else []


def static_url(rel: str) -> str:
    """Versioned static URL: /tools/static/v/<build>/<rel>. Relative imports inside ES modules resolve under the
    same base, so one page load can never mix modules from two builds."""
    return f"{VERSIONED_PREFIX}/{rel.lstrip('/')}"


templates.env.globals.update(site_name=SITE_NAME, base_url=BASE_URL, prefix=TOOLS_PREFIX, tools=TOOLS,
                             api=API_PREFIX, static_url=static_url, rate_per_min=RATE_LIMIT_PER_MIN,
                             glossary_json=GLOSSARY_JSON, toolbox_json=TOOLBOX_JSON, tool_groups=_tool_groups(),
                             categories=CATEGORIES, calculators=CALCULATORS, embed_base=EMBED_BASE_URL,
                             quick_starts=QUICK_STARTS, category_siblings=_category_siblings)

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


@app.exception_handler(turnstile.TurnstileRequired)
async def _turnstile_required(request: Request, exc: turnstile.TurnstileRequired):
    return turnstile.turnstile_required_response(exc)


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
    elif path.startswith(VERSIONED_PREFIX + "/"):
        h["Cache-Control"] = "public, max-age=31536000, immutable" if resp.status_code in (200, 304) else "no-store"
    elif path.startswith(STATIC_PREFIX + "/"):
        h["Cache-Control"] = "public, max-age=300" if resp.status_code in (200, 304) else "no-store"
    else:
        h.setdefault("Cache-Control", "no-cache")
        h["Content-Security-Policy"] = (EMBED_CSP if is_embed else PAGE_CSP).format(nonce=nonce)
    # Access log without query strings or bodies (journald / docker logs).
    if not path.startswith(STATIC_PREFIX + "/") and path != f"{TOOLS_PREFIX}/healthz":
        log.info("%s %s %s %.0fms", request.method, path[:200], resp.status_code, (time.perf_counter() - t0) * 1000)
    return resp


def _tool(slug: str) -> dict:
    return next(t for t in TOOLS if t["slug"] == slug)


CATEGORY_LABEL = {c["key"]: c["label"] for c in CATEGORIES}
UTILITY_APPS = {"subnet-calculator", "port-checker", "email-header-analyzer"}  # UtilitiesApplication; the rest are DeveloperApplication
PUBLISHER = {"@type": "Organization", "name": "BookMyHost", "url": "https://bookmyhost.com"}
OG_W, OG_H = 1200, 630


def og_image_url(slug: str | None) -> str:
    return f"{BASE_URL}{STATIC_PREFIX}/og/{slug or 'index'}.png"


def _related(c: dict) -> list[dict]:
    out = []
    for r in c["related"]:
        t = _tool(r["slug"])
        out.append({"url": f"{TOOLS_PREFIX}/{t['slug']}", "name": t["name"], "anchor": r["anchor"]})
    return out


def _json_ld(slug: str | None, c: dict, url: str) -> str:
    """One @graph per page. Tool pages: WebApplication + FAQPage + BreadcrumbList. Hub: CollectionPage + ItemList + FAQPage
    + BreadcrumbList. No ratings or review counts: nothing here is invented."""
    home = {"@type": "ListItem", "position": 1, "name": "BookMyHost", "item": "https://bookmyhost.com/"}
    hub_url = f"{BASE_URL}{TOOLS_PREFIX}/"
    tools_crumb = {"@type": "ListItem", "position": 2, "name": "Tools", "item": hub_url}
    faq = {"@type": "FAQPage", "@id": f"{url}#faq",
           "mainEntity": [{"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in c["faq"]]}
    if slug:
        tool = _tool(slug)
        crumbs = [home, tools_crumb,
                  {"@type": "ListItem", "position": 3, "name": CATEGORY_LABEL[tool["category"]], "item": f"{hub_url}#cat-{tool['category']}"},
                  {"@type": "ListItem", "position": 4, "name": tool["name"], "item": url}]
        app_node = {
            "@type": "WebApplication", "@id": f"{url}#app", "name": tool["name"], "url": url, "description": tool["short"],
            "applicationCategory": "UtilitiesApplication" if slug in UTILITY_APPS else "DeveloperApplication",
            "operatingSystem": "Any", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": True,
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "INR"},
            "image": og_image_url(slug), "inLanguage": "en", "publisher": PUBLISHER,
        }
        nodes = [app_node, faq, {"@type": "BreadcrumbList", "@id": f"{url}#breadcrumb", "itemListElement": crumbs}]
    else:
        items = [it for g in _tool_groups() for it in g["items"] if not it["external"]]
        nodes = [
            {"@type": "CollectionPage", "@id": f"{url}#page", "name": "BookMyHost Toolbox", "url": url, "description": c["description"],
             "inLanguage": "en", "image": og_image_url(None), "publisher": PUBLISHER, "mainEntity": {"@id": f"{url}#tools"}},
            {"@type": "ItemList", "@id": f"{url}#tools", "name": "BookMyHost Toolbox tools", "numberOfItems": len(items),
             "itemListElement": [{"@type": "ListItem", "position": i, "name": it["name"], "url": f"{BASE_URL}{it['href']}"}
                                 for i, it in enumerate(items, 1)]},
            faq,
            {"@type": "BreadcrumbList", "@id": f"{url}#breadcrumb", "itemListElement": [home, {**tools_crumb, "item": url}]},
        ]
    # "</" must never appear raw inside the JSON-LD <script> block.
    return json.dumps({"@context": "https://schema.org", "@graph": nodes}, ensure_ascii=False).replace("</", "<\\/")


def _render(request: Request, template: str, slug: str | None, **ctx) -> HTMLResponse:
    tool = _tool(slug) if slug else None
    url = f"{BASE_URL}{TOOLS_PREFIX}/{slug}" if slug else f"{BASE_URL}{TOOLS_PREFIX}/"
    c = content_mod.load(slug or content_mod.HUB)
    ctx.setdefault("title", c["title"])
    ctx.setdefault("description", c["description"])
    return templates.TemplateResponse(request, template, {
        "tool": tool, "canonical": url, "faq": c["faq"], "content": c, "related": _related(c), "schema_json": _json_ld(slug, c, url),
        "layout": "shell.html", "embed": False, "noindex": bool(request.query_params.get("q")),
        "og_image": og_image_url(slug), "og_alt": f"{tool['name'] if tool else 'Free developer tools'} - {SITE_NAME}",
        "og_w": OG_W, "og_h": OG_H, "llms_links": slug is None,
        "turnstile_sitekey": config.TURNSTILE_SITEKEY if turnstile.enabled() else "",
        "tool_url": f"{EMBED_BASE_URL}{TOOLS_PREFIX}/{slug}" if slug else "",
        "csp_nonce": request.state.csp_nonce, **ctx,
    })


@app.get(TOOLS_PREFIX, include_in_schema=False)
async def index_redirect():
    return RedirectResponse(f"{TOOLS_PREFIX}/", status_code=301)


@app.get(f"{TOOLS_PREFIX}/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request):
    return _render(request, "index.html", None)


# Bespoke templates (the original seven tools): slug -> (template, extra context factory)
_CUSTOM_PAGES = {
    "spf-dmarc-generator": "generator.html",
    "dns-propagation-checker": "dns.html", "subnet-calculator": "subnet.html", "ttfb-ssl-checker": "ttfb.html",
    "looking-glass": "lg.html", "whois-lookup": "whois.html", "reverse-dns-lookup": "rdns.html", "port-checker": "ports.html",
}


def _make_custom_page(slug: str, template: str):
    async def handler(request: Request):
        extra = {"guide_url": RDNS_GUIDE_URL if RDNS_GUIDE_PUBLISHED else None} if slug == "reverse-dns-lookup" else {}
        return _render(request, template, slug, **extra)
    handler.__name__ = "page_" + slug.replace("-", "_")
    return handler


def _make_page(slug: str):
    async def handler(request: Request):
        return _render(request, "tool_generic.html", slug, page=PAGES[slug])
    handler.__name__ = "page_" + slug.replace("-", "_")
    return handler


for _slug, _tpl in _CUSTOM_PAGES.items():
    app.get(f"{TOOLS_PREFIX}/{_slug}", response_class=HTMLResponse, include_in_schema=False)(_make_custom_page(_slug, _tpl))
for _slug in PAGES:  # email / DNS / BGP suite: one generic template, one JS module per slug
    app.get(f"{TOOLS_PREFIX}/{_slug}", response_class=HTMLResponse, include_in_schema=False)(_make_page(_slug))

_ACCENT_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_EMBED_TEMPLATES = {
    "spf-dmarc-generator": "generator.html",
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
        "noindex": True, "page": PAGES.get(slug), "content": None, "related": [], "og_image": "", "llms_links": False, "theme": theme, "accent": accent, "compact": compact == "1", "embed_host": host or "",
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


_TEXT = "text/plain; charset=utf-8"
_LLMS_HEADERS = {"Cache-Control": "public, max-age=3600"}


@app.get(f"{TOOLS_PREFIX}/llms.txt", include_in_schema=False)
async def llms_txt():
    return Response(llms.build_index(), media_type=_TEXT, headers=_LLMS_HEADERS)


@app.get(f"{TOOLS_PREFIX}/llms-full.txt", include_in_schema=False)
async def llms_full_txt():
    return Response(llms.build_full(), media_type=_TEXT, headers=_LLMS_HEADERS)


@app.get(f"{TOOLS_PREFIX}/sitemap.xml", include_in_schema=False)
async def sitemap():
    urls = [(f"{BASE_URL}{TOOLS_PREFIX}/", TOOLS_HUB_LASTMOD)] + [
        (f"{BASE_URL}{TOOLS_PREFIX}/{t['slug']}", t["lastmod"]) for t in TOOLS]
    body = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    body += "".join(f"  <url><loc>{u}</loc><lastmod>{d}</lastmod><changefreq>monthly</changefreq></url>\n" for u, d in urls)
    body += "</urlset>\n"
    return Response(body, media_type="application/xml", headers={"Cache-Control": "public, max-age=3600"})
