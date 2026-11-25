"""Slice E: SPF & DMARC generator (browser only) and HTTP headers & redirect checker: pages, JS rules, sitemap, llms."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app import content as content_mod
from app import main as main_mod
from app.core.config import TOOLS
from app.main import app

STATIC = Path(main_mod.__file__).parent / "static"
JS = STATIC / "js"
NEW = ["spf-dmarc-generator", "http-headers-checker"]


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def test_tool_entries():
    for slug, cat in (("spf-dmarc-generator", "email"), ("http-headers-checker", "web")):
        t = next(x for x in TOOLS if x["slug"] == slug)
        assert t["category"] == cat and t["badge"] == "new" and t["lastmod"] == "2026-11-25" and t["heavy"] is False and t["embeddable"] is True
    assert next(x for x in TOOLS if x["slug"] == "spf-dmarc-generator").get("client_only") is True
    assert next(x for x in TOOLS if x["slug"] == "spf-dmarc-generator")["group"] == "auth"
    assert not next(x for x in TOOLS if x["slug"] == "http-headers-checker").get("client_only")


@pytest.mark.parametrize("slug", NEW)
def test_js_uses_the_shared_runner(slug):
    t = (JS / "tools" / f"{slug}.js").read_text()
    assert "initTool(" in t or "domainTool(" in t


def test_generator_makes_no_network_call():
    for f in (JS / "tools" / "spf-dmarc-generator.js", JS / "ui" / "spfdmarc.js"):
        t = f.read_text()
        assert "fetch(" not in t and "ctx.api" not in t and "api(" not in t and "XMLHttpRequest" not in t and "sendBeacon" not in t and "WebSocket" not in t, f.name
        assert "localStorage" not in t and "sessionStorage" not in t


async def test_generator_page_renders_builder_and_says_nothing_leaves_the_browser(client):
    r = await client.get("/tools/spf-dmarc-generator")
    assert r.status_code == 200
    t = r.text
    for needle in ('id="gen-form"', 'id="gen-domain"', 'data-include="_spf.google.com"', 'data-include="spf.protection.outlook.com"',
                   'data-include="zoho.in"', 'data-include="zoho.com"', 'data-include="amazonses.com"', 'data-include="sendgrid.net"',
                   'data-include="mailgun.org"', 'data-include="spf.brevo.com"', 'id="spf-ip4"', 'id="spf-ip6"', 'id="spf-include"',
                   'id="spf-all"', 'id="dm-p"', 'id="dm-sp"', 'id="dm-pct"', 'id="dm-rua"', 'id="dm-ruf"', 'id="dm-adkim"', 'id="dm-aspf"', 'id="dm-fo"',
                   'js/tools/spf-dmarc-generator.js'):
        assert needle in t, needle
    assert "nothing leaves your browser" in t.lower()
    assert "Runs in your browser" in (await client.get("/tools/")).text


async def test_headers_page_renders_form(client):
    r = await client.get("/tools/http-headers-checker")
    assert r.status_code == 200
    assert 'id="tool-input"' in r.text and "Check headers" in r.text and "js/tools/http-headers-checker.js" in r.text
    assert (await client.get("/tools/embed/http-headers-checker")).status_code == 200
    assert (await client.get("/tools/embed/spf-dmarc-generator")).status_code == 200


async def test_sitemap_llms_and_hub_include_new_tools(client):
    sm = (await client.get("/tools/sitemap.xml")).text
    llms = (await client.get("/tools/llms.txt")).text
    full = (await client.get("/tools/llms-full.txt")).text
    hub = (await client.get("/tools/")).text
    for slug in NEW:
        assert f"https://bookmyhost.com/tools/{slug}</loc>" in sm
        assert re.search(rf"<loc>https://bookmyhost.com/tools/{slug}</loc>\s*<lastmod>2026-11-25</lastmod>", sm)
        assert f"/tools/{slug}" in llms and f"/tools/{slug}" in hub
        assert f"/tools/{slug}" in full
    assert "/http/headers" in full  # the headers tool documents its API call; the generator has no API


def test_content_claims_match_the_implementation():
    h = content_mod.load("http-headers-checker")
    assert h["curl"] and "/http/headers" in h["curl"]
    assert content_mod.load("spf-dmarc-generator")["curl"] is None
    assert [r["slug"] for r in content_mod.load("spf-dmarc-generator")["related"]] == ["spf-checker", "dmarc-checker", "domain-health", "dkim-checker"]
    assert [r["slug"] for r in h["related"]] == ["ttfb-ssl-checker", "dns-lookup", "whois-lookup", "port-checker"]
    assert "spf-dmarc-generator" in [r["slug"] for r in content_mod.load("spf-checker")["related"]]
    # numbers quoted in the guide must match the grader
    from app.core import httpheaders
    text = json.dumps(h)
    assert str(httpheaders.HSTS_MIN) in text and "8 requests" in text


def test_openapi_documents_headers_endpoint():
    assert "/tools/api/v1/http/headers" in app.openapi()["paths"]


# ---------------------------------------------------------------- builders, run with node when available
NODE = shutil.which("node")


def run_js(expr: str):
    src = f"import * as m from {json.dumps((JS / 'ui' / 'spfdmarc.js').resolve().as_uri())}; console.log(JSON.stringify({expr}));"
    out = subprocess.run([NODE, "--input-type=module", "-e", src], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(out.stdout)


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_spf_builder():
    r = run_js("m.buildSpf({includes:['_spf.google.com','zoho.in'], a:true, mx:false, ip4:'203.0.113.10 198.51.100.0/24', ip6:'2001:db8::25', extraIncludes:'', all:'~all'})")
    assert r["record"] == "v=spf1 ip4:203.0.113.10 ip4:198.51.100.0/24 ip6:2001:db8::25 a include:_spf.google.com include:zoho.in ~all"
    assert r["lookups"] == 3 and r["exact"] is False
    hard = run_js("m.buildSpf({includes:[], all:'-all', ip4:'203.0.113.10'})")
    assert hard["record"] == "v=spf1 ip4:203.0.113.10 -all" and hard["lookups"] == 0 and hard["exact"] is True


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_spf_builder_warnings():
    dup = run_js("m.buildSpf({includes:['_spf.google.com'], extraIncludes:'_spf.google.com', ip4:'1.2.3.4 1.2.3.4 999.1.1.1', ip6:'zzz', all:'~all'})")
    titles = " | ".join(w["title"] for w in dup["warnings"])
    assert "Duplicate entry: include:_spf.google.com" in titles and "Duplicate entry: ip4:1.2.3.4" in titles
    assert "Not a valid IPv4" in titles and "Not a valid IPv6" in titles
    assert dup["record"] == "v=spf1 ip4:1.2.3.4 include:_spf.google.com ~all"
    many = run_js("m.buildSpf({includes:Array.from({length:11},(_, i)=>`s${i}.example.com`), all:'~all'})")
    assert many["lookups"] == 11 and any(w["status"] == "bad" and "over the limit" in w["title"] for w in many["warnings"])
    long = run_js("m.buildSpf({includes:[], ip4:Array.from({length:30},(_, i)=>`203.0.113.${i}/32`).join(' '), all:'~all'})")
    assert long["length"] > 255 and len(long["strings"]) == 3 and "".join(long["strings"]) == long["record"] and all(len(s) <= 255 for s in long["strings"])
    assert any("255" in w["title"] for w in long["warnings"])


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_dmarc_builder():
    r = run_js("m.buildDmarc({p:'quarantine', sp:'reject', pct:'25', rua:'dmarc@example.com, mailto:agg@example.com', ruf:'', adkim:'s', aspf:'r', fo:'1', domain:'https://Example.com/x'})")
    assert r["record"] == "v=DMARC1; p=quarantine; sp=reject; pct=25; rua=mailto:dmarc@example.com,mailto:agg@example.com; adkim=s; fo=1"
    assert r["fqdn"] == "_dmarc.example.com" and r["host"] == "_dmarc"
    assert any("fo is set but there is no ruf" in w["title"] for w in r["warnings"])
    d = run_js("m.buildDmarc({p:'none', pct:'100', rua:'a@example.com', fo:'0', adkim:'r', aspf:'r'})")
    assert d["record"] == "v=DMARC1; p=none; rua=mailto:a@example.com" and d["fqdn"] == "_dmarc.example.com"


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_dmarc_builder_validation():
    r = run_js("m.buildDmarc({p:'none', pct:'150', rua:'not-an-email, ok@other.org', ruf:'', domain:'example.com'})")
    titles = " | ".join(w["title"] for w in r["warnings"])
    assert "pct must be a whole number" in titles and "Not a valid email address in rua" in titles
    assert "Reports go to another domain: other.org" in titles and r["record"] == "v=DMARC1; p=none; rua=mailto:ok@other.org"
    noRua = run_js("m.buildDmarc({p:'none', pct:'100'})")
    assert any("No aggregate report address" in w["title"] for w in noRua["warnings"])
    bad = run_js("m.buildDmarc({p:'none', pct:'50', rua:'a@example.com'})")
    assert any("pct has no effect" in w["title"] for w in bad["warnings"])


def test_generator_run_builds_records():
    """Regression: run() must return built records (render reads spf.warnings), not the raw form inputs."""
    src = (JS / "tools" / "spf-dmarc-generator.js").read_text(encoding="utf-8")
    run_line = next(l for l in src.splitlines() if l.strip().startswith("run:"))
    assert "buildSpf(" in run_line and "buildDmarc(" in run_line
