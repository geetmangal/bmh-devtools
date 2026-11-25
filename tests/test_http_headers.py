"""POST /http/headers: manual redirect following with the SSRF guard on every hop, hop cap, loop detection and grading (offline)."""
import asyncio
import socket

import pytest
from httpx import ASGITransport, AsyncClient

from app.api import http_check
from app.core import cooldown, httpheaders, ratelimit
from app.main import app

API = "/tools/api/v1"
STRONG = {
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff", "x-frame-options": "SAMEORIGIN",
    "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=()",
}


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def fresh_buckets(monkeypatch):
    monkeypatch.setattr(ratelimit, "_bucket", ratelimit.TokenBucket(1000))
    monkeypatch.setattr(cooldown, "_bucket", ratelimit.TokenBucket(1000))


def fake_dns(monkeypatch, table):
    real = socket.getaddrinfo

    def gai(host, port, *a, **kw):
        if host in table:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in table[host]]
        return real(host, port, *a, **kw)
    monkeypatch.setattr(socket, "getaddrinfo", gai)


def fake_fetcher(monkeypatch, script):
    """script(scheme, host, port, path) -> (status, headers). Records every connection attempt."""
    calls = []

    async def fake_fetch_once(scheme, host, port, path, verify=True, pinned=None, max_body=0):
        assert http_check.is_public_ip(pinned[0])  # the socket only ever sees a validated public IP
        calls.append(f"{scheme}://{host}:{port}{path}")
        status, headers = script(scheme, host, port, path)
        return {"ip": pinned[0], "phases": {"dns_ms": 1, "tcp_ms": 1, "tls_ms": 0, "ttfb_ms": 1, "download_ms": 1, "total_ms": 4},
                "http_version": "1.1", "status": status, "reason": "x", "headers": headers, "response_bytes": 0,
                "truncated": False, "tls": None, "tls_error": None}
    monkeypatch.setattr(http_check, "_fetch_once", fake_fetch_once)
    return calls


PUB = {"public.example.net": ["93.184.215.14"], "evil.example.net": ["127.0.0.1"], "meta.example.net": ["169.254.169.254"],
       "lan.example.net": ["10.1.2.3"]}


# ---------------------------------------------------------------- SSRF on every hop
@pytest.mark.parametrize("location", [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/admin", "http://[::1]/", "http://localhost/",
    "http://evil.example.net/", "http://meta.example.net/", "http://lan.example.net/", "ftp://public.example.net/", "file:///etc/passwd",
    "gopher://public.example.net/", "http://public.example.net:22/", "http://public.example.net:6379/", "http://user:pw@public.example.net/",
    "http://2130706433/", "//127.0.0.1/x",
])
async def test_redirect_to_internal_or_odd_target_is_not_followed(client, monkeypatch, location):
    fake_dns(monkeypatch, PUB)
    calls = fake_fetcher(monkeypatch, lambda *a: (302, {"location": location}))
    r = await client.post(f"{API}/http/headers", json={"url": "https://public.example.net/"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert calls == ["https://public.example.net:443/"], calls  # exactly one connection: the first hop
    assert j["flags"]["blocked"] and j["complete"] is False and j["grade"] is None
    assert j["hops"][-1]["status"] is None and j["hops"][-1]["error"]
    assert any(f["id"] == "redirect-blocked" for f in j["findings"])


async def test_first_hop_private_target_refused(client, monkeypatch):
    fake_dns(monkeypatch, PUB)
    calls = fake_fetcher(monkeypatch, lambda *a: (200, {}))
    for u in ("http://127.0.0.1/", "http://169.254.169.254/", "10.0.0.1", "http://evil.example.net/", "http://localhost:8080/"):
        r = await client.post(f"{API}/http/headers", json={"url": u})
        assert r.status_code in (400, 422), (u, r.status_code)
    assert calls == []


async def test_later_hop_resolving_to_private_ip_is_refused_before_connecting(client, monkeypatch):
    fake_dns(monkeypatch, PUB)

    async def no_connect(*a, **kw):
        raise AssertionError(f"connect attempted to {a}")
    monkeypatch.setattr(asyncio, "open_connection", no_connect)
    # first hop is real code path up to the socket: patch only the fetch of hop 1, hop 2 must die in _resolve
    seen = []

    async def first_only(scheme, host, port, path, verify=True, pinned=None, max_body=0):
        seen.append(host)
        if host == "public.example.net":
            return {"ip": pinned[0], "phases": {"total_ms": 3}, "http_version": "1.1", "status": 301, "reason": "", "headers": {"location": "http://evil.example.net/"},
                    "response_bytes": 0, "truncated": False, "tls": None, "tls_error": None}
        raise AssertionError("evil host must not be fetched")
    monkeypatch.setattr(http_check, "_fetch_once", first_only)
    r = await client.post(f"{API}/http/headers", json={"url": "http://public.example.net/"})
    assert r.status_code == 200 and seen == ["public.example.net"]
    assert "non-public" in r.json()["flags"]["blocked"]


# ---------------------------------------------------------------- hop cap + loops
async def test_hop_cap_is_8_requests(client, monkeypatch):
    fake_dns(monkeypatch, PUB)
    calls = fake_fetcher(monkeypatch, lambda s, h, p, path: (302, {"location": f"/n{int(path[2:] or 0) + 1}" if path != "/" else "/n1"}))
    r = await client.post(f"{API}/http/headers", json={"url": "https://public.example.net/"})
    j = r.json()
    assert len(calls) == 8 and len(j["hops"]) == 8
    assert j["flags"]["too_many_hops"] is True and j["complete"] is False and j["grade"] is None
    assert any(f["id"] == "redirect-too-many" and f["status"] == "fail" for f in j["findings"])


async def test_loop_detected(client, monkeypatch):
    fake_dns(monkeypatch, PUB)
    calls = fake_fetcher(monkeypatch, lambda s, h, p, path: (301, {"location": "/b" if path == "/a" else "/a"}))
    r = await client.post(f"{API}/http/headers", json={"url": "https://public.example.net/a"})
    j = r.json()
    assert j["flags"]["loop"] is True and len(calls) == 2 and j["complete"] is False
    assert any(f["id"] == "redirect-loop" for f in j["findings"])


# ---------------------------------------------------------------- chain flags
async def test_bare_domain_starts_on_http_and_flags_missing_https_redirect(client, monkeypatch):
    fake_dns(monkeypatch, PUB)
    calls = fake_fetcher(monkeypatch, lambda *a: (200, {"server": "nginx/1.18.0"}))
    r = await client.post(f"{API}/http/headers", json={"url": "public.example.net"})
    j = r.json()
    assert calls == ["http://public.example.net:80/"]
    assert j["flags"]["no_https_redirect"] is True and j["grade"]["grade"] == "F"
    ids = {f["id"] for f in j["findings"]}
    assert "no-https-redirect" in ids and "leak-server" in ids
    f = next(f for f in j["findings"] if f["id"] == "no-https-redirect")
    assert [t["label"] for t in f["fix_tabs"]] == ["nginx", "Apache (.htaccess)", "LiteSpeed"] and all(t["code"] for t in f["fix_tabs"])


async def test_http_to_https_302_is_flagged_and_final_headers_graded(client, monkeypatch):
    fake_dns(monkeypatch, PUB)

    def script(scheme, host, port, path):
        if scheme == "http":
            return 302, {"location": "https://public.example.net/"}
        return 200, {**STRONG, "set-cookie": "sid=secret", "server": "nginx"}
    fake_fetcher(monkeypatch, script)
    j = (await client.post(f"{API}/http/headers", json={"url": "public.example.net"})).json()
    assert [h["status"] for h in j["hops"]] == [302, 200] and j["flags"]["redirect_count"] == 1
    assert j["flags"]["temporary_redirects"][0]["status"] == 302 and j["flags"]["no_https_redirect"] is False
    assert j["grade"]["grade"] == "A" and j["grade"]["score"] == 100 and j["status"] == "warn"
    assert "set-cookie" not in j["headers"] and j["headers"]["x-content-type-options"] == "nosniff"


async def test_www_mix_and_long_chain(client, monkeypatch):
    fake_dns(monkeypatch, {"example.net": ["93.184.215.14"], "www.example.net": ["93.184.215.14"]})

    def script(scheme, host, port, path):
        if scheme == "http":
            return 301, {"location": "https://example.net/"}
        if host == "example.net":
            return 301, {"location": "https://www.example.net/a"}
        if path == "/a":
            return 301, {"location": "/b"}
        return 200, STRONG
    fake_fetcher(monkeypatch, script)
    j = (await client.post(f"{API}/http/headers", json={"url": "example.net"})).json()
    assert j["flags"]["www_mix"] is True and j["flags"]["long_chain"] is True and j["flags"]["redirect_count"] == 3


async def test_target_cooldown_and_validation(client, monkeypatch):
    monkeypatch.setattr(cooldown, "_bucket", ratelimit.TokenBucket(2, 2))
    fake_dns(monkeypatch, PUB)
    fake_fetcher(monkeypatch, lambda *a: (200, STRONG))
    codes = [(await client.post(f"{API}/http/headers", json={"url": "https://public.example.net/"})).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and codes[-1] == 429
    r = await client.post(f"{API}/http/headers", json={"url": "https://public.example.net/\r\nX: y"})
    assert r.status_code == 422


async def test_connection_error_on_first_hop_is_400(client, monkeypatch):
    fake_dns(monkeypatch, {"down.example.net": ["93.184.215.14"]})

    async def boom(*a, **kw):
        raise OSError("refused")
    monkeypatch.setattr(asyncio, "open_connection", boom)
    r = await client.post(f"{API}/http/headers", json={"url": "https://down.example.net/"})
    assert r.status_code == 400 and "failed" in r.json()["detail"]


# ---------------------------------------------------------------- grading
def g(h, https=True):
    return httpheaders.grade_headers(h, https)


def test_grade_all_strong_is_100_A():
    r = g(STRONG)
    assert r["score"] == 100 and r["grade"] == "A" and all(c["status"] == "ok" for c in r["checks"])


def test_grade_none_is_F():
    r = g({})
    assert r["score"] == 0 and r["grade"] == "F"


def test_grade_without_preload_or_frame_ancestors_is_still_A():
    h = {**STRONG, "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'"}
    r = g(h)
    assert r["score"] == 90 and r["grade"] == "A"  # minus preload (2), includeSubDomains (3), frame-ancestors (5)


def test_grade_short_hsts_is_penalised():
    r = g({**STRONG, "strict-transport-security": "max-age=300"})
    hsts = next(c for c in r["checks"] if c["id"] == "hsts")
    assert hsts["points"] == 8 and hsts["status"] == "warn" and r["score"] == 83 and r["grade"] == "B"


def test_grade_hsts_without_max_age_scores_zero():
    assert next(c for c in g({"strict-transport-security": "includeSubDomains"})["checks"] if c["id"] == "hsts")["points"] == 0


def test_grade_csp_report_only_is_not_enforcing():
    c = next(c for c in g({"content-security-policy-report-only": "default-src 'self'"})["checks"] if c["id"] == "csp")
    assert c["points"] == 5 and c["status"] == "warn"


def test_grade_frame_protection_by_either_header():
    assert next(c for c in g({"x-frame-options": "DENY"})["checks"] if c["id"] == "frame")["points"] == 15
    assert next(c for c in g({"content-security-policy": "frame-ancestors 'none'"})["checks"] if c["id"] == "frame")["points"] == 15
    assert next(c for c in g({"x-frame-options": "ALLOW-FROM https://a.example"})["checks"] if c["id"] == "frame")["status"] == "warn"


def test_grade_referrer_unsafe_url_is_weak_and_nosniff_must_be_exact():
    assert next(c for c in g({"referrer-policy": "unsafe-url"})["checks"] if c["id"] == "referrer")["points"] == 4
    assert next(c for c in g({"x-content-type-options": "sniff"})["checks"] if c["id"] == "xcto")["points"] == 0


def test_grade_plain_http_is_capped_at_F():
    r = g(STRONG, https=False)
    assert r["grade"] == "F" and r["score"] <= 49
    assert next(c for c in r["checks"] if c["id"] == "hsts")["points"] == 0


@pytest.mark.parametrize("score,letter", [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (65, "C"), (64, "D"), (50, "D"), (49, "F"), (0, "F")])
def test_grade_letters(score, letter):
    assert httpheaders.grade_letter(score) == letter


def test_version_leaks_and_header_cleaning():
    assert httpheaders.version_leaks({"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/8.1.2"}) == [("server", "Apache/2.4.41 (Ubuntu)"), ("x-powered-by", "PHP/8.1.2")]
    assert httpheaders.version_leaks({"server": "nginx", "x-powered-by": "Express"}) == []
    cleaned = httpheaders.clean_headers({"set-cookie": "a=b", "authorization": "x", "server": "ng\x00inx" + "A" * 900})
    assert list(cleaned) == ["server"] and len(cleaned["server"]) == 512 and "\x00" not in cleaned["server"]


def test_findings_carry_fix_snippets_for_three_servers():
    grade = g({})
    fs = httpheaders.build_findings(hops=[], flags={"loop": False, "too_many_hops": False, "no_https_redirect": False, "temporary_redirects": [], "long_chain": False,
                                                    "www_mix": False, "redirect_count": 0, "blocked": None},
                                    grade=grade, headers={}, final_status=200, final_https=True, tls_verified=True, complete=True)
    hsts = next(f for f in fs if f["id"] == "hdr-hsts")
    labels = [t["label"] for t in hsts["fix_tabs"]]
    assert labels == ["nginx", "Apache (.htaccess)", "LiteSpeed"]
    assert hsts["fix_tabs"][0]["code"].startswith("add_header Strict-Transport-Security") and hsts["fix_tabs"][1]["code"].startswith("Header always set Strict-Transport-Security")
    assert httpheaders.overall_status(fs) == "fail"


def test_grade_a_partial_header_is_info_not_warn():
    """Regression: a grade-A result must not show an overall Warning just because one header is partly set."""
    from app.core import httpheaders as hh
    grade = {"score": 90, "grade": "A", "checks": [
        {"id": "csp", "label": "Content-Security-Policy", "points": 10, "max": 20, "status": "warn", "value": "x", "note": "partial"}]}
    hops = [{"url": "https://a.example/", "status": 200, "location": None, "ms": 5}]
    flags = hh.analyse_chain(hops, start_https=True, complete=True, loop=False, too_many=False, blocked=None)
    f = hh.build_findings(hops=hops, flags=flags, grade=grade, headers={}, final_status=200,
                          final_https=True, tls_verified=True, complete=True)
    csp = [x for x in f if x["id"] == "hdr-csp"][0]
    assert csp["status"] == "info"


def test_missing_hardening_header_warns_core_header_fails():
    from app.core import httpheaders as hh
    hops = [{"url": "https://a.example/", "status": 200, "location": None, "ms": 5}]
    flags = hh.analyse_chain(hops, start_https=True, complete=True, loop=False, too_many=False, blocked=None)
    grade = {"score": 60, "grade": "C", "checks": [
        {"id": "permissions", "label": "Permissions-Policy", "points": 0, "max": 10, "status": "bad", "value": None, "note": "Missing."},
        {"id": "xcto", "label": "X-Content-Type-Options", "points": 0, "max": 15, "status": "bad", "value": None, "note": "Missing."}]}
    f = {x["id"]: x["status"] for x in hh.build_findings(hops=hops, flags=flags, grade=grade, headers={}, final_status=200,
                                                         final_https=True, tls_verified=True, complete=True)}
    assert f["hdr-permissions"] == "warn" and f["hdr-xcto"] == "fail"
