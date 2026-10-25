"""SSRF, CSP, caching and path-isolation tests (offline: DNS and sockets are monkeypatched)."""
import asyncio
import re
import socket

import pytest
from httpx import ASGITransport, AsyncClient

from app.api import http_check
from app.core import ratelimit
from app.core.validate import ValidationError, is_public_ip, validate_url
from app.main import app

API = "/tools/api/v1"


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def fresh_bucket(monkeypatch):
    monkeypatch.setattr(ratelimit, "_bucket", ratelimit.TokenBucket(1000))


def fake_dns(monkeypatch, table):
    """Make getaddrinfo answer from `table` (name -> list of IPs, or a callable returning one)."""
    real = socket.getaddrinfo

    def gai(host, port, *a, **kw):
        if host in table:
            v = table[host]
            ips = v() if callable(v) else v
            return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                     (ip, port or 0)) for ip in ips]
        return real(host, port, *a, **kw)
    monkeypatch.setattr(socket, "getaddrinfo", gai)


# ---------- address classification ----------
@pytest.mark.parametrize("ip", [
    "160.22.109.1", "160.22.109.2", "160.22.109.9",          # gateway, this host, CloudStack virtual router
    "10.12.200.2", "10.255.255.255", "172.16.0.1", "172.17.0.1", "172.31.255.254", "192.168.1.1",
    "100.64.0.1", "100.127.255.254", "169.254.169.254", "169.254.0.1", "127.0.0.1", "127.8.8.8", "0.0.0.0",
    "::1", "fe80::1", "fd00::1", "::ffff:160.22.109.1", "::ffff:127.0.0.1", "64:ff9b::a00:1",
    "2002:a00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "fe80::1%eth0",
])
def test_blocked_addresses(ip):
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["160.22.109.50", "8.8.8.8", "104.21.54.120", "2606:4700:4700::1111"])
def test_public_addresses(ip):
    assert is_public_ip(ip) is True


@pytest.mark.parametrize("url", [
    "http://160.22.109.1/latest/user-data", "http://160.22.109.9/latest/meta-data/",
    "http://160.22.109.2/", "http://[::ffff:160.22.109.1]/", "http://0x7f000001/", "http://2130706433/",
    "http://017700000001/", "http://intranet/", "http://100.64.1.1/", "http://169.254.169.254/latest/",
])
def test_validate_url_refuses_internal(url):
    with pytest.raises(ValidationError):
        validate_url(url)


# ---------- API level ----------
async def test_api_refuses_gateway_userdata(client):
    r = await client.post(f"{API}/http/check", json={"url": "http://160.22.109.1/latest/user-data"})
    assert r.status_code == 422 and "private" in r.json()["detail"]


@pytest.mark.parametrize("answer", [["127.0.0.1"], ["160.22.109.9"], ["10.0.0.5"], ["93.184.215.14", "127.0.0.1"],
                                    ["::1"], ["169.254.169.254"]])
async def test_api_refuses_name_resolving_internal(client, monkeypatch, answer):
    fake_dns(monkeypatch, {"evil.example.net": answer})

    async def no_connect(*a, **kw):  # must never be reached
        raise AssertionError(f"connect attempted to {a}")
    monkeypatch.setattr(asyncio, "open_connection", no_connect)
    r = await client.post(f"{API}/http/check", json={"url": "http://evil.example.net/"})
    assert r.status_code == 400 and "non-public" in r.json()["detail"], r.text


async def test_dns_rebinding_connects_only_to_pinned_ip(client, monkeypatch):
    """The name answers public first and 127.0.0.1 afterwards; the socket must only ever see the
    first, validated IP literal (never the name, never the rebound address)."""
    answers = iter([["93.184.215.14"]] + [["127.0.0.1"]] * 20)
    fake_dns(monkeypatch, {"rebind.example.net": lambda: next(answers)})
    seen = []

    async def record(host, port, *a, **kw):
        seen.append(host)
        raise OSError("blocked in test")
    monkeypatch.setattr(asyncio, "open_connection", record)
    r = await client.post(f"{API}/http/check", json={"url": "http://rebind.example.net/"})
    assert r.status_code == 400
    assert seen == ["93.184.215.14"], seen


async def test_fetch_once_refuses_private_pinned_ip():
    with pytest.raises(http_check.CheckError):
        await http_check._fetch_once("http", "example.com", 80, "/", pinned=("160.22.109.1", 0.0))


@pytest.mark.parametrize("location", ["http://10.0.0.1/", "http://160.22.109.1/latest/user-data",
                                      "http://127.0.0.1:8080/", "http://localhost/", "http://evil.example.net/"])
async def test_redirect_to_internal_refused(client, monkeypatch, location):
    fake_dns(monkeypatch, {"public.example.net": ["93.184.215.14"], "evil.example.net": ["127.0.0.1"]})
    calls = []

    async def fake_fetch_once(scheme, host, port, path, verify=True, pinned=None):
        calls.append((host, pinned))
        assert http_check.is_public_ip(pinned[0])
        return {"ip": pinned[0], "phases": {"dns_ms": 1, "tcp_ms": 1, "tls_ms": 0, "ttfb_ms": 1,
                                            "download_ms": 1, "total_ms": 4},
                "http_version": "1.1", "status": 302, "reason": "Found", "headers": {"location": location},
                "response_bytes": 0, "truncated": False, "tls": None, "tls_error": None}
    monkeypatch.setattr(http_check, "_fetch_once", fake_fetch_once)
    r = await client.post(f"{API}/http/check", json={"url": "http://public.example.net/"})
    assert r.status_code == 400, r.text
    assert "redirect" in r.json()["detail"] or "non-public" in r.json()["detail"]
    assert [h for h, _ in calls] == ["public.example.net"]


async def test_concurrency_gate_returns_503(monkeypatch):
    from fastapi import HTTPException
    monkeypatch.setattr(ratelimit, "QUEUE_WAIT", 0.05)
    gate = ratelimit.Gate(1, "HTTP")
    async with gate.slot():
        with pytest.raises(HTTPException) as ei:
            async with gate.slot():
                pass
    assert ei.value.status_code == 503


# ---------- headers, CSP, caching, paths ----------
async def test_page_csp_nonce_and_no_inline_script(client):
    r = await client.get("/tools/ttfb-ssl-checker")
    csp = r.headers["content-security-policy"]
    m = re.search(r"script-src 'self' 'nonce-([A-Za-z0-9_-]+)'", csp)
    assert m and "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    nonce = m.group(1)
    for tag in re.findall(r"<script\b[^>]*>", r.text):
        assert f'nonce="{nonce}"' in tag, tag
    assert "onclick=" not in r.text and "cdn.tailwindcss.com" not in r.text
    assert re.search(r'href="/tools/static/css/tools\.css\?v=[0-9a-f]+"', r.text)
    assert r.headers["cache-control"] == "no-cache"
    r2 = await client.get("/tools/ttfb-ssl-checker")
    assert r2.headers["content-security-policy"] != csp  # fresh nonce per response


async def test_api_not_cached_and_noindex(client):
    r = await client.post(f"{API}/subnet/calc", json={"cidr": "10.0.0.0/22"})
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store" and r.headers["x-robots-tag"] == "noindex"
    r = await client.get(f"{API}/openapi.json")
    assert r.headers["cache-control"] == "no-store"
    paths = r.json()["paths"]
    assert paths and all(p.startswith("/tools/api/v1/") for p in paths), list(paths)


async def test_static_cache_headers(client):
    r = await client.get("/tools/static/js/common.js?v=abc")
    assert r.status_code == 200 and "immutable" in r.headers["cache-control"]


async def test_nothing_outside_tools_prefix(client):
    for path in ["/api/v1/subnet/calc", "/api/v1/docs", "/api/v1/openapi.json", "/healthz", "/robots.txt",
                 "/static/js/dns.js", "/docs", "/openapi.json"]:
        r = await client.get(path)
        assert r.status_code == 404, path
    r = await client.post("/api/v1/subnet/calc", json={"cidr": "10.0.0.0/24"})
    assert r.status_code in (404, 405)


async def test_docs_page_nonce(client):
    r = await client.get(f"{API}/docs")
    assert r.status_code == 200
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", r.headers["content-security-policy"]).group(1)
    assert all(f'nonce="{nonce}"' in t for t in re.findall(r"<script\b[^>]*>", r.text))


async def test_rate_limit_key_ignores_spoofed_xff(client, monkeypatch):
    monkeypatch.setattr(ratelimit, "_bucket", ratelimit.TokenBucket(3))
    codes = []
    for i in range(5):  # rotating X-Forwarded-For must not buy a fresh bucket
        r = await client.post(f"{API}/subnet/calc", json={"cidr": "10.0.0.0/24"},
                              headers={"X-Real-IP": "198.51.100.7", "X-Forwarded-For": f"203.0.113.{i}"})
        codes.append(r.status_code)
    assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
