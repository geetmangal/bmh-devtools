"""Toolbox GUI v3 slice D: MTA-STS & TLS-RPT checker, BIMI checker, What is my IP (pages, sitemap, llms, shortcuts, /mail/tls-rpt)."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.api import mail
from app.core import cooldown, ratelimit
from app.core.config import TOOLS
from app.core.mailcheck import tlsrpt
from app.core.mailcheck.resolver import FakeResolver
from app.main import app

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / "app" / "static" / "js"
API = "/tools/api/v1"
D_SLUGS = ["mta-sts-checker", "bimi-checker", "what-is-my-ip"]
VISITOR = {"X-Real-IP": "93.184.215.14", "User-Agent": "pytest-browser/1.0"}


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    big = lambda: ratelimit.TokenBucket(1000, 1000)  # noqa: E731
    monkeypatch.setattr(ratelimit, "_bucket", big())
    monkeypatch.setattr(mail, "_bucket", big())
    monkeypatch.setattr(mail, "_cache", type(mail._cache)(60))
    monkeypatch.setattr(cooldown, "_bucket", ratelimit.TokenBucket(1000, 1000))


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


def tool(slug):
    return next(t for t in TOOLS if t["slug"] == slug)


# ---------------------------------------------------------------- config
def test_tool_entries():
    for slug in D_SLUGS:
        t = tool(slug)
        assert t["lastmod"] == "2026-11-25" and t["badge"] == "new" and t["embeddable"] is True and t["heavy"] is False
    assert tool("mta-sts-checker")["category"] == "email" and tool("mta-sts-checker")["group"] == "auth"
    assert tool("bimi-checker")["category"] == "email" and tool("bimi-checker")["group"] == "auth"
    assert tool("mta-sts-checker")["accepts"] == ["domain", "email"] == tool("bimi-checker")["accepts"]
    assert tool("what-is-my-ip")["category"] == "network" and tool("what-is-my-ip")["accepts"] == []
    assert len({t["slug"] for t in TOOLS}) == len(TOOLS)


# ---------------------------------------------------------------- pages, sitemap, llms
@pytest.mark.parametrize("slug", D_SLUGS)
async def test_pages_render_sitemap_llms(client, slug):
    r = await client.get(f"/tools/{slug}")
    assert r.status_code == 200 and "<h1" in r.text and 'id="results"' in r.text and f"js/tools/{slug}.js" in r.text
    assert r.text.index("<h1") < r.text.index('<form id="tool-form"')
    s = (await client.get("/tools/sitemap.xml")).text
    assert f"<loc>https://bookmyhost.com/tools/{slug}</loc><lastmod>2026-11-25</lastmod>" in s
    assert f"](https://bookmyhost.com/tools/{slug}" in (await client.get("/tools/llms.txt")).text
    assert (await client.get(f"/tools/embed/{slug}")).status_code == 200


async def test_what_is_my_ip_has_no_text_input(client):
    t = (await client.get("/tools/what-is-my-ip")).text
    form = re.search(r'<form id="tool-form".*?</form>', t, re.S).group(0)
    assert 'required' not in form and "Check again" in form


def test_js_modules():
    for slug in D_SLUGS:
        text = (JS / "tools" / f"{slug}.js").read_text()
        assert "initTool(" in text or "domainTool(" in text
    assert "/mail/mta-sts" in (JS / "tools" / "mta-sts-checker.js").read_text()
    assert "/mail/tls-rpt" in (JS / "tools" / "mta-sts-checker.js").read_text()
    assert "/mail/bimi" in (JS / "tools" / "bimi-checker.js").read_text()
    ip = (JS / "tools" / "what-is-my-ip.js").read_text()
    assert "/ports/myip" in ip and "/rdns/lookup" in ip and "/prefix-whois/" in ip and "initTool(" in ip


def test_omnibox_hint_lists_new_shortcuts():
    shell = (ROOT / "app" / "templates" / "shell.html").read_text()
    assert all(w in shell for w in ("bimi:", "mtasts:", "headers:", "myip"))


# ---------------------------------------------------------------- detect.js shortcuts (run under node)
NODE = shutil.which("node")


def run_detect(script: str):
    code = ("const d = await import(process.argv[1]);" + script)
    out = subprocess.run([NODE, "--input-type=module", "-e", code, (JS / "ui" / "detect.js").as_uri()], capture_output=True, text=True, timeout=30, check=True)
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_detect_shortcuts():
    tools = [{"slug": s, "accepts": []} for s in D_SLUGS]
    res = run_detect(f"""const T = {json.dumps(tools)};
      const r = (s) => d.route(d.detect(s), T);
      console.log(JSON.stringify({{
        bimi: r('bimi:example.com'), mtasts: r('mtasts:example.com'), mta: r('mta-sts:example.com'), myip: r('myip'), mail: r('mtasts:me@example.com'),
        headers_absent: r('headers:example.com'), plain: r('example.com'), myipType: d.detect('myip').type}}));""")
    assert res["bimi"] == {"slug": "bimi-checker", "params": {"q": "example.com"}}
    assert res["mtasts"]["slug"] == "mta-sts-checker" and res["mta"]["slug"] == "mta-sts-checker"
    assert res["mail"]["params"]["q"] == "example.com"
    assert res["myip"] == {"slug": "what-is-my-ip", "params": {}} and res["myipType"] == "myip"
    assert res["headers_absent"] is None and res["plain"] is None  # no http-headers-checker / domain-health in this list


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_detect_headers_shortcut_routes_when_tool_exists():
    tools = [{"slug": "http-headers-checker", "accepts": ["url", "domain"]}]
    res = run_detect(f"""const T = {json.dumps(tools)};
      console.log(JSON.stringify([d.route(d.detect('headers:example.com'), T), d.route(d.detect('headers:https://example.com/a'), T)]));""")
    assert res[0] == {"slug": "http-headers-checker", "params": {"q": "example.com"}}
    assert res[1]["params"]["q"] == "https://example.com/a"


# ---------------------------------------------------------------- POST /mail/tls-rpt
def use_zone(monkeypatch, zone):
    monkeypatch.setattr(tlsrpt, "get_default_resolver", lambda: FakeResolver(zone))


async def test_tls_rpt_record_found(client, monkeypatch):
    use_zone(monkeypatch, {"_smtp._tls.example.com/TXT": ["v=TLSRPTv1; rua=mailto:tls@example.com,https://rpt.example.net/r"]})
    r = await client.post(f"{API}/mail/tls-rpt", json={"domain": "example.com"}, headers=VISITOR)
    assert r.status_code == 200
    j = r.json()
    assert j["check"] == "tlsrpt" and j["target"] == "example.com" and j["status"] == "pass"
    assert j["data"]["record"].startswith("v=TLSRPTv1") and j["data"]["rua"] == ["mailto:tls@example.com", "https://rpt.example.net/r"]
    assert {f["id"] for f in j["findings"]} == {"tlsrpt_ok"}


async def test_tls_rpt_missing_and_bad_rua(client, monkeypatch):
    use_zone(monkeypatch, {"example.com/A": ["192.0.2.1"]})
    j = (await client.post(f"{API}/mail/tls-rpt", json={"domain": "example.com"}, headers=VISITOR)).json()
    assert j["status"] == "info" and j["data"]["record"] is None and "tlsrpt_missing" in {f["id"] for f in j["findings"]}
    assert any("_smtp._tls.example.com" in (f.get("fix_record") or "") for f in j["findings"])
    use_zone(monkeypatch, {"_smtp._tls.bad.example/TXT": ["v=TLSRPTv1; rua=ftp://x.example"], "bad.example/A": ["192.0.2.1"]})
    j = (await client.post(f"{API}/mail/tls-rpt", json={"domain": "bad.example"}, headers=VISITOR)).json()
    assert "tlsrpt_bad_rua" in {f["id"] for f in j["findings"]} and j["status"] != "pass"


async def test_tls_rpt_rejects_bad_domain_and_is_cached(client, monkeypatch):
    use_zone(monkeypatch, {"_smtp._tls.example.com/TXT": ["v=TLSRPTv1; rua=mailto:t@example.com"]})
    assert (await client.post(f"{API}/mail/tls-rpt", json={"domain": "not a domain"}, headers=VISITOR)).status_code == 422
    first = (await client.post(f"{API}/mail/tls-rpt", json={"domain": "example.com"}, headers=VISITOR)).json()
    second = (await client.post(f"{API}/mail/tls-rpt", json={"domain": "example.com"}, headers=VISITOR)).json()
    assert first["cache"]["hit"] is False and second["cache"]["hit"] is True
