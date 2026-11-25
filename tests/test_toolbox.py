"""Toolbox shell, Turnstile tool pass, embeds and glossary (offline: Cloudflare and probes are mocked)."""
import json
import re

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app import main as main_mod
from app.api import lookingglass, pass_, portcheck
from app.core import config, ratelimit, turnstile
from app.core.config import CALCULATORS, CATEGORIES, TOOLS
from app.main import app

API = "/tools/api/v1"
IP = "93.184.215.14"
VISITOR = {"X-Real-IP": IP, "User-Agent": "pytest-browser/1.0"}
SECRET = "unit-test-pass-secret"


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setattr(ratelimit, "_bucket", ratelimit.TokenBucket(1000))
    for mod in (lookingglass, portcheck):
        monkeypatch.setattr(mod, "_bucket", ratelimit.TokenBucket(1000))
    monkeypatch.setattr(pass_, "_bucket", ratelimit.TokenBucket(config.PASS_RATE_PER_MIN))
    monkeypatch.setattr(main_mod, "_embed_bucket", ratelimit.TokenBucket(config.EMBED_RATE_PER_MIN))
    main_mod._embed_refs.clear()
    # Turnstile is OFF unless a test turns it on, whatever the environment says.
    for k in ("TURNSTILE_SITEKEY", "TURNSTILE_SECRET", "TOOLS_PASS_SECRET"):
        monkeypatch.setattr(config, k, "")
    monkeypatch.setattr(config, "TURNSTILE_BYPASS_IPS", [])


@pytest.fixture
def ts_on(monkeypatch):
    monkeypatch.setattr(config, "TURNSTILE_SITEKEY", "1x00000000000000000000AA")
    monkeypatch.setattr(config, "TURNSTILE_SECRET", "secret-not-real")
    monkeypatch.setattr(config, "TOOLS_PASS_SECRET", SECRET)


@pytest.fixture
def fake_probe(monkeypatch):
    async def probe(ip, port):
        return {"port": port, "service": None, "state": "open", "ms": 5}
    monkeypatch.setattr(portcheck, "probe", probe)


# ---------- tool pass: issue / check ----------
def test_pass_valid(ts_on):
    p = turnstile.issue_pass("203.0.113.5", "UA/1")
    assert turnstile.check_pass(p, "203.0.113.5", "UA/1")
    assert turnstile.check_pass(p, "203.0.113.250", "UA/1")  # same /24


def test_pass_expired(ts_on):
    p = turnstile.issue_pass("203.0.113.5", "UA/1", now=1_000_000)
    assert turnstile.check_pass(p, "203.0.113.5", "UA/1", now=1_000_000 + config.PASS_TTL - 1)
    assert not turnstile.check_pass(p, "203.0.113.5", "UA/1", now=1_000_000 + config.PASS_TTL + 1)


def test_pass_wrong_network_and_ua(ts_on):
    p = turnstile.issue_pass("203.0.113.5", "UA/1")
    assert not turnstile.check_pass(p, "203.0.114.5", "UA/1")
    assert not turnstile.check_pass(p, "203.0.113.5", "Other/2")


def test_pass_ipv6_uses_48(ts_on):
    p = turnstile.issue_pass("2001:db8:abcd:1::1", "UA")
    assert turnstile.check_pass(p, "2001:db8:abcd:ffff::9", "UA")
    assert not turnstile.check_pass(p, "2001:db8:abce::1", "UA")


def test_pass_tampered(ts_on):
    p = turnstile.issue_pass("203.0.113.5", "UA/1")
    payload, sig = p.split(".")
    other = turnstile.issue_pass("198.51.100.5", "UA/1").split(".")[0]
    assert not turnstile.check_pass(other + "." + sig, "203.0.113.5", "UA/1")
    assert not turnstile.check_pass(payload + "." + sig[:-2] + "AA", "203.0.113.5", "UA/1")
    for bad in ("", "x", "a.b.c", None, "." , "!!!.???"):
        assert not turnstile.check_pass(bad, "203.0.113.5", "UA/1")


def test_pass_needs_the_server_secret(ts_on, monkeypatch):
    p = turnstile.issue_pass("203.0.113.5", "UA/1")
    monkeypatch.setattr(config, "TOOLS_PASS_SECRET", "another-secret")
    assert not turnstile.check_pass(p, "203.0.113.5", "UA/1")


# ---------- POST /pass ----------
async def test_pass_endpoint_success(client, ts_on, monkeypatch):
    seen = {}

    async def ok(token, ip):
        seen.update(token=token, ip=ip)
        return True
    monkeypatch.setattr(turnstile, "verify", ok)
    r = await client.post(f"{API}/pass", json={"token": "tok"}, headers=VISITOR)
    assert r.status_code == 200 and r.json()["expires_in"] == 900 and seen == {"token": "tok", "ip": IP}
    assert turnstile.check_pass(r.json()["pass"], IP, VISITOR["User-Agent"])


async def test_pass_endpoint_rejected_token(client, ts_on, monkeypatch):
    async def no(token, ip):
        return False
    monkeypatch.setattr(turnstile, "verify", no)
    r = await client.post(f"{API}/pass", json={"token": "bad"}, headers=VISITOR)
    assert r.status_code == 403 and "pass" not in r.json()


async def test_pass_endpoint_cloudflare_unreachable_is_503(client, ts_on, monkeypatch):
    async def down(token, ip):
        raise httpx.ConnectError("boom")
    monkeypatch.setattr(turnstile, "verify", down)
    r = await client.post(f"{API}/pass", json={"token": "t"}, headers=VISITOR)
    assert r.status_code == 503


async def test_verify_uses_5s_timeout_and_siteverify_url(ts_on, monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, **kw):
            captured["timeout"] = kw.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, data=None):
            captured.update(url=url, data=data)
            return httpx.Response(200, json={"success": True}, request=httpx.Request("POST", url))
    monkeypatch.setattr(turnstile.httpx, "AsyncClient", FakeClient)
    assert await turnstile.verify("tok", "1.2.3.4") is True
    assert captured["timeout"] == 5.0 and captured["url"] == "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    assert captured["data"]["response"] == "tok" and captured["data"]["remoteip"] == "1.2.3.4"


async def test_pass_endpoint_rate_limited_10_per_min(client, ts_on, monkeypatch):
    async def no(token, ip):
        return False
    monkeypatch.setattr(turnstile, "verify", no)
    codes = [(await client.post(f"{API}/pass", json={"token": "x"}, headers=VISITOR)).status_code for _ in range(12)]
    assert codes[:10] == [403] * 10 and codes[10] == 429


async def test_pass_endpoint_off_when_disabled(client):
    r = await client.post(f"{API}/pass", json={"token": "x"}, headers=VISITOR)
    assert r.status_code == 404


# ---------- heavy endpoints ----------
def test_heavy_flags_match_the_protected_routes():
    assert {t["slug"] for t in TOOLS if t["heavy"]} == {"looking-glass", "port-checker", "domain-health", "blacklist-check", "smtp-test", "asn-lookup", "bgp-prefix-lookup"}


async def test_heavy_requires_pass_when_enabled(client, ts_on, fake_probe):
    for path, body in (("/lg/run", {"target": "8.8.8.8", "tool": "ping"}), ("/lg/bgp", {"target": "8.8.8.8"}), ("/ports/check", {"common": True})):
        r = await client.post(API + path, json=body, headers=VISITOR)
        assert r.status_code == 403 and r.json() == {"error": "pass_required"}, path
        r = await client.post(API + path, json=body, headers={**VISITOR, "X-Tools-Pass": "garbage"})
        assert r.status_code == 403, path


async def test_heavy_with_valid_pass_reaches_the_handler(client, ts_on, fake_probe):
    p = turnstile.issue_pass(IP, VISITOR["User-Agent"])
    h = {**VISITOR, "X-Tools-Pass": p}
    r = await client.post(f"{API}/ports/check", json={"port": 443}, headers=h)
    assert r.status_code == 200 and r.json()["results"][0]["state"] == "open"
    # the SSRF guard still runs behind the pass: a private target is refused (422), not 403
    r = await client.post(f"{API}/lg/run", json={"target": "127.0.0.1", "tool": "ping"}, headers=h)
    assert r.status_code == 422
    # a pass for another UA is useless
    r = await client.post(f"{API}/ports/check", json={"port": 443}, headers={**VISITOR, "User-Agent": "other", "X-Tools-Pass": p})
    assert r.status_code == 403


async def test_heavy_is_noop_when_disabled(client, fake_probe):
    r = await client.post(f"{API}/ports/check", json={"port": 443}, headers=VISITOR)
    assert r.status_code == 200


async def test_heavy_bypass_ip(client, ts_on, fake_probe, monkeypatch):
    monkeypatch.setattr(config, "TURNSTILE_BYPASS_IPS", ["93.184.215.0/24", "not-a-cidr"])
    r = await client.post(f"{API}/ports/check", json={"port": 443}, headers=VISITOR)
    assert r.status_code == 200
    r = await client.post(f"{API}/ports/check", json={"port": 443}, headers={"X-Real-IP": "93.185.1.1"})
    assert r.status_code == 403


# ---------- embeds ----------
async def test_embed_is_frameable_and_noindex(client):
    r = await client.get("/tools/embed/looking-glass?theme=dark&q=1.1.1.1", headers={"Referer": "https://blog.example.org/post"})
    assert r.status_code == 200
    assert "x-frame-options" not in r.headers
    assert "frame-ancestors *" in r.headers["content-security-policy"]
    assert '<meta name="robots" content="noindex,follow">' in r.text
    assert '<link rel="canonical" href="https://bookmyhost.com/tools/looking-glass">' in r.text
    assert 'data-theme="dark"' in r.text and 'id="cmdbar"' not in r.text and 'tabrail' not in r.text
    m = re.search(r'<a href="([^"]+)" target="_blank" rel="noopener">Powered by BookMyHost</a>', r.text)
    assert m and "utm_source=blog.example.org" in m[1] and "utm_medium=widget" in m[1] and "utm_campaign=tools-embed" in m[1].replace("&amp;", "&")
    assert main_mod._embed_refs["blog.example.org"] == 1  # hostnames only


async def test_embed_without_referer_uses_embed_source(client):
    r = await client.get("/tools/embed/subnet-calculator")
    assert "utm_source=embed" in r.text.replace("&amp;", "&")


async def test_only_embed_paths_are_frameable(client):
    for path in ("/tools/", "/tools/looking-glass", "/tools/subnet-calculator", f"{API}/subnet/calc", "/tools/sitemap.xml", "/tools/embed.js"):
        r = await client.get(path) if path != f"{API}/subnet/calc" else await client.post(path, json={"cidr": "10.0.0.0/24"})
        assert r.headers["x-frame-options"] == "DENY", path
        assert "frame-ancestors *" not in r.headers["content-security-policy"], path
    r = await client.get("/tools/looking-glass")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


async def test_embed_unknown_slug_404(client):
    assert (await client.get("/tools/embed/nope")).status_code == 404
    assert (await client.get("/tools/embed/")).status_code in (404, 307, 308)


async def test_embed_accent_validated(client):
    ok = await client.get("/tools/embed/port-checker?accent=%23ff6600")
    assert 'style="--accent: #ff6600"' in ok.text
    for bad in ("red", "%23ff66", "%23ff6600;}body{display:none", "expression(1)", "%23GGGGGG"):
        r = await client.get(f"/tools/embed/port-checker?accent={bad}")
        assert r.status_code == 200 and "--accent" not in r.text and "display:none" not in r.text, bad


async def test_embed_theme_and_compact(client):
    r = await client.get("/tools/embed/port-checker?theme=bogus&compact=1")
    assert "data-theme" not in r.text and 'data-compact="1"' in r.text
    assert 'data-embed="1"' in r.text


async def test_embed_js_served_with_fixed_schema(client):
    r = await client.get("/tools/embed.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert "bmh-tools:resize" in r.text and "ev.origin !== origin" in r.text and "iframe[data-bmh-tool]" in r.text


async def test_embed_pages_not_in_sitemap(client):
    r = await client.get("/tools/sitemap.xml")
    assert r.text.count("<loc>") == len(config.TOOLS) + 1 and "/embed" not in r.text


async def test_embed_api_calls_have_own_bucket(client):
    body = {"cidr": "10.0.0.0/22"}
    h = {"X-Real-IP": "198.51.100.9", "X-Tools-Embed": "site-a.example"}
    codes = [(await client.post(f"{API}/subnet/calc", json=body, headers=h)).status_code for _ in range(config.EMBED_RATE_PER_MIN + 2)]
    assert codes[:config.EMBED_RATE_PER_MIN] == [200] * config.EMBED_RATE_PER_MIN and codes[-1] == 429
    # other embedding site, same IP: own bucket
    assert (await client.post(f"{API}/subnet/calc", json=body, headers={**h, "X-Tools-Embed": "site-b.example"})).status_code == 200
    # direct (non-embed) calls are not counted in the embed bucket
    assert (await client.post(f"{API}/subnet/calc", json=body, headers={"X-Real-IP": "198.51.100.9"})).status_code == 200


def test_clean_host():
    assert main_mod.clean_host("https://Blog.Example.org:8080/a?b=1") == "blog.example.org"
    assert main_mod.clean_host("example.org") == "example.org"
    assert main_mod.clean_host("javascript:alert(1)") is None
    assert main_mod.clean_host("a b") is None and main_mod.clean_host("") is None and main_mod.clean_host(None) is None


# ---------- CSP ----------
async def test_page_csp_allows_turnstile_only_where_needed(client):
    csp = (await client.get("/tools/port-checker")).headers["content-security-policy"]
    for d in ("script-src", "frame-src", "connect-src"):
        part = [x for x in csp.split(";") if x.strip().startswith(d)][0]
        assert "https://challenges.cloudflare.com" in part, d
    assert "unsafe-inline" not in [x for x in csp.split(";") if x.strip().startswith("script-src")][0]
    assert "'nonce-" in csp


# ---------- shell, tabs, config, glossary ----------
def test_tool_config_fields():
    cats = {c["key"] for c in CATEGORIES}
    assert [c["label"] for c in CATEGORIES] == ["Email & Deliverability", "DNS & Domains", "Website & SSL", "Network & BGP", "More from BookMyHost"]
    kinds = {"ip", "prefix", "asn", "domain", "email", "url", "host"}
    expect = {"looking-glass": "network", "port-checker": "network", "dns-propagation-checker": "dns", "reverse-dns-lookup": "dns",
              "whois-lookup": "dns", "ttfb-ssl-checker": "web", "subnet-calculator": "network",
              "domain-health": "email", "mx-lookup": "email", "spf-checker": "email", "dmarc-checker": "email", "dkim-checker": "email",
              "blacklist-check": "email", "smtp-test": "email", "email-header-analyzer": "email", "dns-lookup": "dns",
              "asn-lookup": "network", "bgp-prefix-lookup": "network",
                  "mta-sts-checker": "email", "bimi-checker": "email", "what-is-my-ip": "network", "spf-dmarc-generator": "email", "http-headers-checker": "web"}
    for t in TOOLS:
        assert t["category"] == expect[t["slug"]] and t["category"] in cats
        assert t["icon"] and set(t["accepts"]) <= kinds and isinstance(t["heavy"], bool) and t["embeddable"] is True
    assert [c["url"] for c in CALCULATORS] == [
        "https://bookmyhost.com/free-tools/cloud-cost-gst-calculator",
        "https://bookmyhost.com/free-tools/vps-sizing-calculator",
        "https://bookmyhost.com/free-tools/noida-latency-test"]
    assert [t["slug"] for t in TOOLS] == ["domain-health", "blacklist-check", "smtp-test", "email-header-analyzer", "mx-lookup", "spf-checker", "dmarc-checker", "dkim-checker", "mta-sts-checker", "bimi-checker", "spf-dmarc-generator", "dns-propagation-checker", "whois-lookup", "reverse-dns-lookup", "dns-lookup", "ttfb-ssl-checker", "http-headers-checker", "subnet-calculator", "looking-glass", "port-checker", "asn-lookup", "bgp-prefix-lookup", "what-is-my-ip"]


@pytest.mark.parametrize("path", ["/tools/"] + [f"/tools/{t['slug']}" for t in TOOLS])
async def test_pages_render_shell(client, path):
    r = await client.get(path)
    assert r.status_code == 200
    assert ('id="cmdbar"' in r.text) == (path == "/tools/")
    assert path == "/tools/" or 'aria-label="Breadcrumb"' in r.text
    assert "BookMyHost " in r.text and 'text-accent">Toolbox</span>' in r.text
    for t in TOOLS:
        assert f'href="/tools/{t["slug"]}"' in r.text
    for c in CALCULATORS:
        assert f'href="{c["url"]}"' in r.text
    assert 'data-mode-btn="beginner"' in r.text and 'data-mode-btn="expert"' in r.text and "data-theme-toggle" in r.text
    assert 'id="glossary"' in r.text and 'type="module"' in r.text
    assert "noindex" not in r.text.lower()
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", r.headers["content-security-policy"])[1]
    assert all(f'nonce="{nonce}"' in t for t in re.findall(r"<script\b[^>]*>", r.text))
    assert not re.search(r"\son(click|load|change|submit)=", r.text)


async def test_tool_pages_have_embed_drawer_and_results_region(client):
    r = await client.get("/tools/dns-propagation-checker")
    assert 'id="embed"' in r.text and 'data-embed-base="https://www.bookmyhost.com/tools/embed/"' in r.text
    assert 'aria-live="polite"' in r.text and 'id="results"' in r.text
    assert 'aria-current="page"' in r.text
    assert 'id="embed"' not in (await client.get("/tools/")).text


async def test_q_urls_are_noindex_follow(client):
    r = await client.get("/tools/subnet-calculator?q=10.0.0.0/24")
    assert '<meta name="robots" content="noindex,follow">' in r.text
    assert 'rel="canonical" href="https://bookmyhost.com/tools/subnet-calculator"' in r.text


async def test_sitekey_exposed_only_when_enabled(client, ts_on):
    assert 'data-turnstile-sitekey="1x00000000000000000000AA"' in (await client.get("/tools/looking-glass")).text
    assert 'data-turnstile-sitekey="1x00000000000000000000AA"' in (await client.get("/tools/embed/looking-glass")).text


async def test_sitekey_empty_when_disabled(client):
    assert 'data-turnstile-sitekey=""' in (await client.get("/tools/looking-glass")).text


def test_glossary_json_valid():
    from pathlib import Path
    g = json.loads((Path(main_mod.ROOT) / "data" / "glossary.json").read_text(encoding="utf-8"))
    assert len(g) >= 40
    for k, e in g.items():
        assert e["name"] and len(e["def"]) > 30, k
        assert all(isinstance(m, str) for m in e.get("match", []))
    for need in ("asn", "bgp", "rpki", "roa", "irr", "ptr", "fcrdns", "dkim-selector", "dmarc", "mta-sts", "tls-rpt", "ttfb", "san",
                 "port-open", "port-closed", "port-filtered", "ttl-dns", "ttl-ip", "epp-status", "dnssec", "caa", "rdap"):
        assert need in g, need


async def test_glossary_is_injected_into_pages(client):
    r = await client.get("/tools/reverse-dns-lookup")
    m = re.search(r'<script type="application/json" id="glossary" nonce="[^"]+">(.*?)</script>', r.text, re.S)
    assert m and "fcrdns" in json.loads(m[1])
    assert "</script" not in m[1].lower()
