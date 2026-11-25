"""Toolbox v2: mail/DNSBL/SMTP/health/BGP endpoints, per-target cooldown, pages, embeds and the land outline.
Offline: every engine is replaced with a stub."""
import json
import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app import main as main_mod
from app.api import bgp as bgp_api
from app.api import dnsbl as dnsbl_api
from app.api import health as health_api
from app.api import lookingglass, mail, pass_, portcheck
from app.api import smtp as smtp_api
from app.core import config, cooldown, ratelimit, turnstile
from app.core.config import TOOLS
from app.core.mailcheck.models import CheckResult
from app.main import app

API = "/tools/api/v1"
VISITOR = {"X-Real-IP": "93.184.215.14", "User-Agent": "pytest-browser/1.0"}
SECRET = "unit-test-pass-secret"
NEW = ["domain-health", "mx-lookup", "spf-checker", "dmarc-checker", "dkim-checker", "blacklist-check", "smtp-test",
       "email-header-analyzer", "dns-lookup", "asn-lookup", "bgp-prefix-lookup"]


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    big = lambda: ratelimit.TokenBucket(1000, 1000)  # noqa: E731
    monkeypatch.setattr(ratelimit, "_bucket", big())
    for mod in (lookingglass, portcheck, mail, dnsbl_api, smtp_api, health_api, bgp_api):
        monkeypatch.setattr(mod, "_bucket", big())
    monkeypatch.setattr(mail, "_probe_bucket", big())
    monkeypatch.setattr(bgp_api, "_gp_bucket", big())
    for mod in (mail, dnsbl_api, smtp_api, health_api):
        mod._cache.clear() if hasattr(mod._cache, "clear") else monkeypatch.setattr(mod, "_cache", type(mod._cache)(60))
    for name in ("_asn_cache", "_prefix_cache"):
        monkeypatch.setattr(bgp_api, name, type(getattr(bgp_api, name))(60))
    monkeypatch.setattr(cooldown, "_bucket", ratelimit.TokenBucket(1000, 1000))
    monkeypatch.setattr(pass_, "_bucket", ratelimit.TokenBucket(config.PASS_RATE_PER_MIN))
    monkeypatch.setattr(main_mod, "_embed_bucket", ratelimit.TokenBucket(config.EMBED_RATE_PER_MIN))
    for k in ("TURNSTILE_SITEKEY", "TURNSTILE_SECRET", "TOOLS_PASS_SECRET"):
        monkeypatch.setattr(config, k, "")
    monkeypatch.setattr(config, "TURNSTILE_BYPASS_IPS", [])


@pytest.fixture
def ts_on(monkeypatch):
    monkeypatch.setattr(config, "TURNSTILE_SITEKEY", "1x00000000000000000000AA")
    monkeypatch.setattr(config, "TURNSTILE_SECRET", "secret-not-real")
    monkeypatch.setattr(config, "TOOLS_PASS_SECRET", SECRET)


def with_pass():
    return {**VISITOR, "X-Tools-Pass": turnstile.issue_pass(VISITOR["X-Real-IP"], VISITOR["User-Agent"])}


def result(check, target="example.com", **kw):
    return CheckResult(check=check, target=target, status=kw.pop("status", "pass"), summary=kw.pop("summary", "ok"), **kw)


def ndjson(r):
    assert r.headers["content-type"].startswith("application/x-ndjson")
    return [json.loads(x) for x in r.text.splitlines() if x.strip()]


# ---------- mail ----------
@pytest.mark.parametrize("path,mod_name", [("mx", "mx"), ("spf", "spf"), ("dmarc", "dmarc"), ("bimi", "bimi"), ("mta-sts", "mta_sts"), ("dns", "dnsrec")])
async def test_mail_endpoints_validate_and_answer(client, monkeypatch, path, mod_name):
    async def fake(domain, *a, **k):
        return result(mod_name, domain)
    monkeypatch.setattr(getattr(mail, mod_name), "check", fake)
    bad = await client.post(f"{API}/mail/{path}", json={"domain": "not a domain!"}, headers=VISITOR)
    assert bad.status_code == 422
    r = await client.post(f"{API}/mail/{path}", json={"domain": "Example.com"}, headers=VISITOR)
    assert r.status_code == 200
    d = r.json()
    assert d["check"] == mod_name and d["status"] == "pass" and d["target"] == "example.com"
    assert r.headers["cache-control"] == "no-store"


async def test_mail_rejects_ip_and_private_names(client):
    for dom in ("127.0.0.1", "localhost", "10.0.0.1"):
        assert (await client.post(f"{API}/mail/spf", json={"domain": dom}, headers=VISITOR)).status_code == 422


async def test_dkim_selector_is_light_but_probing_needs_a_pass(client, monkeypatch, ts_on):
    seen = []

    async def fake(domain, selector=None):
        seen.append(selector)
        return result("dkim", domain)
    monkeypatch.setattr(mail.dkim, "check", fake)
    r = await client.post(f"{API}/mail/dkim", json={"domain": "example.com", "selector": "google"}, headers=VISITOR)
    assert r.status_code == 200 and seen == ["google"]
    r = await client.post(f"{API}/mail/dkim", json={"domain": "example.com"}, headers=VISITOR)
    assert r.status_code == 403 and r.json() == {"error": "pass_required"}
    r = await client.post(f"{API}/mail/dkim", json={"domain": "example.com"}, headers=with_pass())
    assert r.status_code == 200 and seen[-1] is None


# ---------- blocklists ----------
def stub_dnsbl(monkeypatch, n=3):
    rows = [{"name": f"list{i}", "zone": f"z{i}.test", "type": "ip", "status": "listed" if i == 0 else "clear", "listed": i == 0, "code": "127.0.0.2" if i == 0 else None,
             "reason": None, "weight": 1, "delist_url": "https://example.test/delist" if i == 0 else None, "query": "q", "ms": 5, "note": None} for i in range(n)]

    async def fake_iter(target):
        for r in rows:
            yield r
    monkeypatch.setattr(dnsbl_api.dnsbl, "iter_check", fake_iter)
    monkeypatch.setattr(dnsbl_api.dnsbl, "load_lists", lambda: [{"type": "ip"}] * n)


async def test_dnsbl_validation_stream_shape_and_pass(client, monkeypatch, ts_on):
    stub_dnsbl(monkeypatch)
    assert (await client.post(f"{API}/dnsbl/check", json={"target": "8.8.8.8"}, headers=VISITOR)).status_code == 403
    r = await client.post(f"{API}/dnsbl/check", json={"target": "not a target"}, headers=with_pass())
    assert r.status_code == 422
    r = await client.post(f"{API}/dnsbl/check", json={"target": "8.8.8.8"}, headers=with_pass())
    assert r.status_code == 200
    lines = ndjson(r)
    assert [x["type"] for x in lines] == ["list", "list", "list", "summary"]
    assert lines[0]["done"] == 1 and lines[0]["total"] == 3 and lines[0]["row"]["status"] == "listed"
    s = lines[-1]["result"]
    assert s["data"]["counts"]["listed"] == 1 and s["status"] in ("fail", "warn")


# ---------- SMTP ----------
async def test_smtp_disabled_gives_info_without_a_pass(client, monkeypatch, ts_on):
    monkeypatch.delenv("BMH_TOOLS_SMTP_ENABLED", raising=False)
    r = await client.post(f"{API}/smtp/check", json={"host": "mail.example.com", "port": 25}, headers=VISITOR)
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "info" and d["data"]["enabled"] is False and d["data"]["applicable"] is False


async def test_smtp_enabled_needs_pass_and_validates(client, monkeypatch, ts_on):
    monkeypatch.setenv("BMH_TOOLS_SMTP_ENABLED", "1")

    async def fake(host, port):
        return result("smtp", host, data={"host": host, "port": port, "steps": [{"step": "connect", "ok": True, "ms": 3, "detail": ""}]})
    monkeypatch.setattr(smtp_api.smtpcheck, "check", fake)
    body = {"host": "93.184.215.14", "port": 587}
    assert (await client.post(f"{API}/smtp/check", json=body, headers=VISITOR)).status_code == 403
    assert (await client.post(f"{API}/smtp/check", json={**body, "port": 22}, headers=with_pass())).status_code == 422
    assert (await client.post(f"{API}/smtp/check", json={"host": "127.0.0.1", "port": 25}, headers=with_pass())).status_code == 422
    r = await client.post(f"{API}/smtp/check", json=body, headers=with_pass())
    assert r.status_code == 200 and r.json()["data"]["port"] == 587


# ---------- domain health ----------
async def test_health_stream_shape_pass_and_validation(client, monkeypatch, ts_on):
    async def fake_iter(domain, dkim_selector=None):
        for name in ("mx", "spf"):
            yield {"type": "check", "name": name, "result": result(name, domain).to_dict(), "elapsed_ms": 4}
        yield {"type": "summary", "summary": {"domain": domain, "score": 91, "grade": "A", "areas": [], "radar": [], "capped_by": None, "fixes": [], "counts": {}, "checks": {}}}
    monkeypatch.setattr(health_api.health, "iter_health", fake_iter)
    assert (await client.post(f"{API}/health/domain", json={"domain": "example.com"}, headers=VISITOR)).status_code == 403
    assert (await client.post(f"{API}/health/domain", json={"domain": "bad domain"}, headers=with_pass())).status_code == 422
    r = await client.post(f"{API}/health/domain", json={"domain": "example.com"}, headers=with_pass())
    lines = ndjson(r)
    assert [x["type"] for x in lines] == ["check", "check", "summary"]
    assert lines[0]["name"] == "mx" and lines[0]["done"] == 1 and lines[1]["done"] == 2
    assert lines[-1]["summary"]["grade"] == "A"


async def test_stream_failure_becomes_an_error_line(client, monkeypatch):
    async def boom(domain, dkim_selector=None):
        raise RuntimeError("engine exploded")
        yield  # pragma: no cover
    monkeypatch.setattr(health_api.health, "iter_health", boom)
    lines = ndjson(await client.post(f"{API}/health/domain", json={"domain": "example.com"}, headers=VISITOR))
    assert lines[-1]["type"] == "error" and "exploded" not in json.dumps(lines[-1])


# ---------- BGP ----------
async def test_asn_and_prefix_endpoints(client, monkeypatch, ts_on):
    async def asn_report(n):
        return {"asn": n, "name": "TEST-AS", "announced": True, "summary": "ok", "findings": [], "graph": {"nodes": [], "edges": []}}

    async def prefix_report(res):
        return {"prefix": "1.1.1.0/24", "queried": "1.1.1.0/24", "announced": True, "summary": "ok", "origins": [], "findings": []}
    monkeypatch.setattr(bgp_api.bgpview, "asn_report", asn_report)
    monkeypatch.setattr(bgp_api.bgpview, "prefix_report", prefix_report)
    for path in ("/asn/13335", "/prefix/1.1.1.0/24"):
        assert (await client.get(API + path, headers=VISITOR)).status_code == 403, path
    assert (await client.get(f"{API}/asn/notanumber", headers=with_pass())).status_code == 422
    assert (await client.get(f"{API}/prefix/999.1.1.0/24", headers=with_pass())).status_code == 422
    r = await client.get(f"{API}/asn/AS13335", headers=with_pass())
    assert r.status_code == 200 and r.json()["asn"] in (13335, "13335", "AS13335")
    r = await client.get(f"{API}/prefix/1.1.1.0/24", headers=with_pass())
    assert r.status_code == 200 and r.json()["prefix"] == "1.1.1.0/24"


async def test_lg_global_stream(client, monkeypatch, ts_on):
    seen = {}

    async def engine(kind, target, preset, limit):
        seen["args"] = (kind, preset, limit)
        yield {"event": "created", "id": "x", "probes_count": 2, "type": "ping"}
        yield {"event": "probe", "index": 0, "probe": {"probe": {"city": "Mumbai", "country": "IN", "asn": 1}, "status": "finished", "stats": {"avg": 12.0, "loss": 0}, "hops": []}}
        yield {"event": "done", "id": "x", "type": "ping", "probes": [{"big": "payload"}]}
    monkeypatch.setattr(bgp_api.globalping, "run", engine)
    body = {"target": "1.1.1.1", "type": "ping", "preset": "india", "limit": 2}
    assert (await client.post(f"{API}/lg/global", json=body, headers=VISITOR)).status_code == 403
    assert (await client.post(f"{API}/lg/global", json={**body, "preset": "mars"}, headers=with_pass())).status_code == 422
    assert (await client.post(f"{API}/lg/global", json={**body, "target": "127.0.0.1"}, headers=with_pass())).status_code == 422
    r = await client.post(f"{API}/lg/global", json=body, headers=with_pass())
    lines = ndjson(r)
    assert [x["type"] for x in lines] == ["created", "probe", "done"] and "probes" not in lines[-1]
    assert lines[1]["probe"]["probe"]["city"] == "Mumbai"
    assert seen["args"] == ("ping", "india", 2)


# ---------- per-target cooldown ----------
async def test_target_cooldown_returns_429_target_busy(client, monkeypatch):
    monkeypatch.setattr(cooldown, "_bucket", ratelimit.TokenBucket(2, 2))
    stub_dnsbl(monkeypatch)
    codes = []
    for _ in range(4):
        r = await client.post(f"{API}/dnsbl/check", json={"target": "8.8.8.8"}, headers=VISITOR)
        codes.append(r.status_code)
    assert codes[:2] == [200, 200] and codes[-1] == 429
    assert r.json() == {"error": "target_busy"} and "retry-after" in r.headers
    # a different target is unaffected, and the key is normalised (case)
    assert (await client.post(f"{API}/dnsbl/check", json={"target": "1.1.1.1"}, headers=VISITOR)).status_code == 200


def test_cooldown_normalises_targets():
    assert cooldown.norm(" Example.COM. ") == cooldown.norm("example.com")


# ---------- looking glass enrichment ----------
async def test_lg_traceroute_hops_are_enriched(client, monkeypatch):
    from tests.test_nettools import fake_dns
    fake_dns(monkeypatch, {"ok.example.net": ["93.184.215.14"]})

    async def fake_run(argv, timeout):
        return 0, "traceroute to 93.184.215.14, 30 hops max\n 1  10.1.1.1  0.5 ms\n 2  93.184.215.14  9.9 ms\n", False

    async def fake_enrich(hops, loss_pct=None):
        out = [{**h, "asn": None if h["ip"].startswith("10.") else 15133, "as_name": "EDGECAST", "city": "Ashburn", "country": "US", "lat": 39.0, "lon": -77.5, "private": h["ip"].startswith("10.")} for h in hops]
        return {"hops": out, "segments": [{"asn": 15133, "as_name": "EDGECAST", "private": False, "start_hop": 2, "end_hop": 2, "hops": [2], "hop_count": 1, "label": "AS15133 EDGECAST", "rtt_ms": 9.9, "country": "US"}], "summary": "2 hops through 1 network."}
    monkeypatch.setattr(lookingglass, "_run", fake_run)
    monkeypatch.setattr(lookingglass, "_enrich", fake_enrich)
    r = await client.post(f"{API}/lg/run", json={"target": "ok.example.net", "tool": "traceroute"}, headers=VISITOR)
    d = r.json()
    assert r.status_code == 200 and d["reached"] is True
    assert d["path_summary"] == "2 hops through 1 network." and d["segments"][0]["asn"] == 15133
    h2 = d["hops"][1]
    assert h2["ip"] == "93.184.215.14" and h2["asn"] == 15133 and h2["as_name"] and h2["city"] == "Ashburn" and h2["lat"] == 39.0 and d["hops"][0]["private"] is True
    assert {"hop", "ip", "rtt_ms"} <= set(h2)  # old fields kept


# ---------- pages, tabs, embeds, sitemap ----------
@pytest.mark.parametrize("slug", NEW)
async def test_new_pages_render_with_commandbar_and_active_tab(client, slug):
    r = await client.get(f"/tools/{slug}")
    assert r.status_code == 200
    assert 'id="cmdbar"' in r.text and 'id="results"' in r.text and "<h1" in r.text and "FAQPage" in r.text
    assert re.search(r'<meta name="description" content="[^"]{40,}', r.text)
    assert re.search(rf'href="/tools/{slug}"[^>]*aria-current="page"|aria-current="page"[^>]*href="/tools/{slug}"', r.text)
    assert f"js/tools/{slug}.js" in r.text
    assert not re.search(r"\son(click|load|change|submit)=", r.text)
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", r.headers["content-security-policy"])[1]
    assert all(f'nonce="{nonce}"' in t for t in re.findall(r"<script\b[^>]*>", r.text))


@pytest.mark.parametrize("slug", NEW)
async def test_new_tools_embed_and_sitemap(client, slug):
    t = next(x for x in TOOLS if x["slug"] == slug)
    assert t["embeddable"] is True and t["lastmod"] == "2026-11-25"
    r = await client.get(f"/tools/embed/{slug}")
    assert r.status_code == 200 and 'id="results"' in r.text and f"js/tools/{slug}.js" in r.text
    s = (await client.get("/tools/sitemap.xml")).text
    assert f"<loc>https://bookmyhost.com/tools/{slug}</loc><lastmod>2026-11-25</lastmod>" in s


async def test_email_tab_is_visible_and_header_analyzer_takes_no_api(client):
    r = await client.get("/tools/spf-checker")
    assert ">Email<" in r.text
    h = await client.get("/tools/email-header-analyzer")
    assert "nothing leaves your browser" in h.text.lower()
    js = (Path(main_mod.__file__).parent / "static/js/tools/email-header-analyzer.js").read_text()
    assert "api(" not in js and "fetch(" not in js


def test_land_outline_exists_and_is_small():
    p = Path(main_mod.__file__).parent / "static/viz/land-110m.svgpath.txt"
    assert p.exists() and 5_000 < p.stat().st_size < 150 * 1024
    d = p.read_text()
    assert d.startswith("M") and d.rstrip().endswith("z")


async def test_land_outline_is_served(client):
    r = await client.get("/tools/static/viz/land-110m.svgpath.txt")
    assert r.status_code == 200 and r.text.startswith("M")
