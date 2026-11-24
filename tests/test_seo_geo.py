"""SEO / GEO phase: versioned static assets, page content, JSON-LD, meta tags, OG images, llms.txt and next-step links."""
import html
import json
import re
import struct
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app import content as content_mod
from app import main as main_mod
from app.core.config import CATEGORIES, TOOLS
from app.main import VERSIONED_PREFIX, app

SLUGS = [t["slug"] for t in TOOLS]
STATIC = Path(main_mod.__file__).parent / "static"
JS = STATIC / "js"


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def graph(text: str) -> list[dict]:
    blocks = re.findall(r'<script type="application/ld\+json"[^>]*>(.*?)</script>', text, re.S)
    assert len(blocks) == 1, "exactly one JSON-LD block per page"
    data = json.loads(blocks[0])
    assert data["@context"] == "https://schema.org" and isinstance(data["@graph"], list)
    return data["@graph"]


def meta(text: str, name: str, attr: str = "name") -> str:
    m = re.search(rf'<meta {attr}="{re.escape(name)}" content="([^"]*)"', text)
    assert m, name
    return html.unescape(m.group(1))


# ---------------------------------------------------------------- 1. cache busting
async def test_versioned_static_is_immutable_and_unversioned_is_short(client):
    r = await client.get(f"{VERSIONED_PREFIX}/js/ui/dom.js")
    assert r.status_code == 200 and r.headers["cache-control"] == "public, max-age=31536000, immutable"
    r = await client.get("/tools/static/js/ui/dom.js")
    assert r.status_code == 200 and r.headers["cache-control"] == "public, max-age=300"
    r = await client.get("/tools/static/js/ui/dom.js?v=whatever")  # old query-string URLs: still served, never immutable
    assert r.status_code == 200 and "immutable" not in r.headers["cache-control"]


async def test_unknown_build_segment_is_404_and_not_cached(client):
    r = await client.get("/tools/static/v/0000deadbeef/js/ui/dom.js")
    assert r.status_code == 404 and r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("slug", ["spf-checker", "looking-glass", "bgp-prefix-lookup"])
async def test_pages_load_every_asset_from_the_versioned_path(client, slug):
    t = (await client.get(f"/tools/{slug}")).text
    assert f'href="{VERSIONED_PREFIX}/css/tools.css"' in t
    assert f'src="{VERSIONED_PREFIX}/js/shell.js"' in t and f'src="{VERSIONED_PREFIX}/js/tools/{slug}.js"' in t
    assert "?v=" not in t and "/tools/static/js/" not in t


def test_every_relative_import_resolves_to_a_file_so_modules_stay_under_one_build():
    seen = 0
    for f in JS.rglob("*.js"):
        text = f.read_text(encoding="utf-8")
        static_imports = re.findall(r"^\s*(?:import|export)\b[^'\"\n]*?\bfrom\s*['\"]([^'\"]+)['\"]", text, re.M)
        dynamic_imports = re.findall(r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]", text)
        specs = static_imports + dynamic_imports
        for spec in specs:
            assert spec.startswith("."), f"{f.name}: bare/absolute import {spec} would escape the versioned base"
            assert (f.parent / spec).resolve().is_file(), f"{f.name} imports missing {spec}"
            seen += 1
    assert seen > 50
    wm = (JS / "viz/worldmap.js").read_text(encoding="utf-8")
    assert "import.meta.url" in wm and "/static/viz/land" not in wm.replace("app/static/viz/land", "")  # the land outline is fetched relative to the module


def test_build_id_env_override_and_hash(monkeypatch):
    monkeypatch.setenv("BMH_TOOLS_BUILD", "abc123/../x y")
    assert main_mod._compute_build() == "abc123..xy"
    monkeypatch.setenv("BMH_TOOLS_BUILD", "..")
    assert re.fullmatch(r"[0-9a-f]{12}", main_mod._compute_build())  # unusable value: fall back to the content hash
    monkeypatch.delenv("BMH_TOOLS_BUILD")
    assert re.fullmatch(r"[0-9a-f]{12}", main_mod._compute_build())  # content hash of the static tree, stable between calls
    assert main_mod._compute_build() == main_mod._compute_build()


# ---------------------------------------------------------------- 2. content
@pytest.mark.parametrize("slug", SLUGS + ["hub"])
def test_content_files_are_complete(slug):
    c = content_mod.load(slug)
    assert len(c["answer"].split()) >= 25 and c["answer"].endswith("."), "direct answer"
    n = content_mod.guide_word_count(c)
    assert (400 if slug == "hub" else 600) <= n <= 800, f"{slug}: {n} words"
    assert 5 <= len(c["faq"]) <= 6 and all(len(q) == 2 and q[0].endswith("?") for q in c["faq"])
    assert 3 <= len(c["related"]) <= 4
    for r in c["related"]:
        assert r["slug"] in SLUGS and r["slug"] != slug and len(r["anchor"].split()) >= 3, r
    assert c["og_line"] and not re.search(r"@(API|BASE|RATE)@", json.dumps(c))  # no unfilled tokens
    if slug != "hub":
        assert c["inputs"] and c["outputs"] and (c["curl"] is None) == (slug == "email-header-analyzer")


@pytest.mark.parametrize("slug", SLUGS)
async def test_tool_page_renders_answer_guide_faq_and_related(client, slug):
    r = await client.get(f"/tools/{slug}")
    assert r.status_code == 200
    c = content_mod.load(slug)
    t = r.text
    plain = html.unescape(t)
    assert 'data-direct-answer' in t and c["answer"] in plain
    for s in c["sections"]:
        assert s["h"] in plain and s["p"][0] in plain
    assert t.count("<details") >= len(c["faq"])
    rel = re.search(r"<ul[^>]*data-related>(.*?)</ul>", t, re.S).group(1)
    hrefs = re.findall(r'href="(/tools/[a-z-]+)"', rel)
    assert len(hrefs) == len(c["related"]) and f"/tools/{slug}" not in hrefs
    for rr in c["related"]:
        assert f'href="/tools/{rr["slug"]}"' in rel and rr["anchor"] in html.unescape(rel)


async def test_hub_renders_answer_and_related(client):
    t = (await client.get("/tools/")).text
    assert "data-direct-answer" in t and "data-related" in t and all(f'id="cat-{c["key"]}"' in t for c in CATEGORIES)


# ---------------------------------------------------------------- 3. schema + meta
@pytest.mark.parametrize("slug", SLUGS)
async def test_tool_json_ld(client, slug):
    t = (await client.get(f"/tools/{slug}")).text
    g = graph(t)
    assert sorted(n["@type"] for n in g) == ["BreadcrumbList", "FAQPage", "WebApplication"]
    url = f"https://bookmyhost.com/tools/{slug}"
    app_ = next(n for n in g if n["@type"] == "WebApplication")
    tool = next(x for x in TOOLS if x["slug"] == slug)
    assert app_["url"] == url and app_["name"] == tool["name"] and app_["operatingSystem"] == "Any"
    assert app_["applicationCategory"] in ("DeveloperApplication", "UtilitiesApplication")
    assert app_["isAccessibleForFree"] is True and app_["publisher"]["name"] == "BookMyHost"
    assert app_["offers"] == {"@type": "Offer", "price": "0", "priceCurrency": "INR"}
    faq = next(n for n in g if n["@type"] == "FAQPage")
    assert [q["name"] for q in faq["mainEntity"]] == [q for q, _ in content_mod.load(slug)["faq"]]
    crumbs = next(n for n in g if n["@type"] == "BreadcrumbList")["itemListElement"]
    label = next(c["label"] for c in CATEGORIES if c["key"] == tool["category"])
    assert [c["name"] for c in crumbs] == ["BookMyHost", "Tools", label, tool["name"]]
    assert [c["position"] for c in crumbs] == [1, 2, 3, 4] and crumbs[-1]["item"] == url
    blob = json.dumps(g)
    assert "AggregateRating" not in blob and '"@type": "Review"' not in blob and "ratingValue" not in blob


async def test_hub_json_ld(client):
    g = graph((await client.get("/tools/")).text)
    assert sorted(n["@type"] for n in g) == ["BreadcrumbList", "CollectionPage", "FAQPage", "ItemList"]
    items = next(n for n in g if n["@type"] == "ItemList")["itemListElement"]
    assert sorted(i["url"] for i in items) == sorted(f"https://bookmyhost.com/tools/{s}" for s in SLUGS)
    assert [i["position"] for i in items] == list(range(1, 19))
    assert "AggregateRating" not in json.dumps(g)


async def test_titles_and_descriptions_are_unique_and_within_limits(client):
    seen_t, seen_d = {}, {}
    for slug in SLUGS + [None]:
        r = await client.get(f"/tools/{slug}" if slug else "/tools/")
        title = html.unescape(re.search(r"<title>(.*?)</title>", r.text).group(1))
        desc = meta(r.text, "description")
        assert len(title) < 60, (slug, len(title), title)
        assert 140 <= len(desc) <= 160, (slug, len(desc))
        assert title not in seen_t and desc not in seen_d, slug
        seen_t[title], seen_d[desc] = slug, slug
        assert meta(r.text, "og:title", "property") == title and meta(r.text, "og:description", "property") == desc


async def test_q_result_urls_are_noindex_follow_with_canonical_to_the_tool_page(client):
    for slug in ("spf-checker", "dns-propagation-checker", "looking-glass"):
        r = await client.get(f"/tools/{slug}?q=example.com")
        assert '<meta name="robots" content="noindex,follow">' in r.text
        assert f'<link rel="canonical" href="https://bookmyhost.com/tools/{slug}">' in r.text
        clean = await client.get(f"/tools/{slug}")
        assert "noindex" not in clean.text.lower()
    r = await client.get("/tools/?q=8.8.8.8")
    assert "noindex,follow" in r.text and '<link rel="canonical" href="https://bookmyhost.com/tools/">' in r.text


# ---------------------------------------------------------------- 4. OG images
@pytest.mark.parametrize("slug", SLUGS + [None])
async def test_og_image_tags_and_file(client, slug):
    r = await client.get(f"/tools/{slug}" if slug else "/tools/")
    name = slug or "index"
    img = meta(r.text, "og:image", "property")
    assert img == f"https://bookmyhost.com/tools/static/og/{name}.png"
    assert meta(r.text, "og:image:width", "property") == "1200" and meta(r.text, "og:image:height", "property") == "630"
    assert "BookMyHost Toolbox" in meta(r.text, "og:image:alt", "property")
    assert meta(r.text, "twitter:card") == "summary_large_image" and meta(r.text, "twitter:image") == img
    f = STATIC / "og" / f"{name}.png"
    data = f.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) < 80 * 1024
    assert struct.unpack(">II", data[16:24]) == (1200, 630)
    served = await client.get(f"/tools/static/og/{name}.png")
    assert served.status_code == 200 and served.headers["content-type"] == "image/png"


async def test_embed_pages_have_no_og_image_and_stay_noindex(client):
    r = await client.get("/tools/embed/spf-checker")
    assert "og:image" not in r.text and "noindex,follow" in r.text


# ---------------------------------------------------------------- 5. GEO
async def test_llms_txt(client):
    r = await client.get("/tools/llms.txt")
    assert r.status_code == 200 and r.headers["content-type"] == "text/plain; charset=utf-8"
    assert r.headers["cache-control"] == "public, max-age=3600"
    t = r.text
    assert t.startswith("# BookMyHost Toolbox\n\n> ")
    for tool in TOOLS:
        assert f"[{tool['name']}](https://bookmyhost.com/tools/{tool['slug']}): {tool['short']}" in t
    assert t.count("](https://bookmyhost.com/tools/") >= 18
    for cat in CATEGORIES:
        if cat["key"] != "calc":
            assert f"## {cat['label']}" in t
    assert "/tools/api/v1/docs" in t and "/tools/api/v1/openapi.json" in t and "embed" in t.lower()
    assert "llms-full.txt" in t


async def test_llms_full_txt(client):
    r = await client.get("/tools/llms-full.txt")
    assert r.status_code == 200 and r.headers["content-type"] == "text/plain; charset=utf-8"
    assert r.headers["cache-control"] == "public, max-age=3600"
    t = r.text
    assert t.count("\n## ") == 18
    for tool in TOOLS:
        c = content_mod.load(tool["slug"])
        assert f"## {tool['name']}" in t and f"URL: https://bookmyhost.com/tools/{tool['slug']}" in t
        assert f"Direct answer: {c['answer']}" in t and f"Inputs: {c['inputs']}" in t
        if c["curl"]:
            assert c["curl"] in t and c["curl"].startswith("curl ")
    assert "Turnstile" in t and "X-Tools-Pass" in t and "No API" in t  # heavy endpoints + the browser-only tool
    assert "@API@" not in t and "@BASE@" not in t


async def test_hub_head_links_to_llms_files_and_tool_pages_do_not(client):
    t = (await client.get("/tools/")).text
    assert '<link rel="alternate" type="text/plain" href="https://bookmyhost.com/tools/llms.txt"' in t
    assert '<link rel="alternate" type="text/plain" href="https://bookmyhost.com/tools/llms-full.txt"' in t
    assert 'type="text/plain"' not in (await client.get("/tools/spf-checker")).text


async def test_robots_and_sitemap_behaviour_unchanged(client):
    s = (await client.get("/tools/sitemap.xml")).text
    assert s.count("<loc>") == 19 and "llms" not in s and "/api/" not in s and "/static/" not in s
    r = await client.get("/tools/api/v1/openapi.json")
    assert r.headers["x-robots-tag"] == "noindex" and r.headers["cache-control"] == "no-store"
    assert (await client.get("/robots.txt")).status_code == 404  # robots.txt belongs to the host site
    assert "x-robots-tag" not in (await client.get("/tools/llms.txt")).headers


# ---------------------------------------------------------------- 6. internal linking in result cards
def test_result_pages_offer_contextual_next_steps():
    helper = (JS / "ui/findings.js").read_text(encoding="utf-8")
    assert "export function nextSteps" in helper and "data-next-steps" in helper
    want = {"spf-checker": "dmarc-checker", "dmarc-checker": "dkim-checker", "dkim-checker": "dmarc-checker",
            "mx-lookup": "spf-checker", "blacklist-check": "reverse-dns-lookup", "reverse-dns-lookup": "blacklist-check",
            "asn-lookup": "bgp-prefix-lookup", "bgp-prefix-lookup": "asn-lookup", "dns-lookup": "spf-checker"}
    for slug, nxt in want.items():
        src = (JS / "tools" / f"{slug}.js").read_text(encoding="utf-8")
        assert "nextSteps(" in src and f"slug: '{nxt}'" in src, slug
