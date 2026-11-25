"""Strict Turnstile + tight rate limit on POST /smtp/check only (other heavy tools keep the plain pass)."""
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.api import portcheck, smtp
from app.core import config, ratelimit, smtpcheck, turnstile
from app.main import app

API = "/tools/api/v1"
IP = "93.184.215.14"
UA = "pytest-browser/1.0"
VISITOR = {"X-Real-IP": IP, "User-Agent": UA}
BODY = {"host": "93.184.215.14", "port": 25}


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.setattr(ratelimit, "_bucket", ratelimit.TokenBucket(1000))
    monkeypatch.setattr(smtp, "_bucket", ratelimit.TokenBucket(1000))
    monkeypatch.setattr(portcheck, "_bucket", ratelimit.TokenBucket(1000))
    monkeypatch.setattr(smtp, "_strict", ratelimit.TokenBucket(smtp.STRICT_RUNS / smtp.STRICT_WINDOW_MIN, smtp.STRICT_RUNS))
    monkeypatch.setattr(smtp, "_cache", smtp.TTLCache(60))
    monkeypatch.setattr(config, "TURNSTILE_SITEKEY", "1x00000000000000000000AA")
    monkeypatch.setattr(config, "TURNSTILE_SECRET", "secret-not-real")
    monkeypatch.setattr(config, "TOOLS_PASS_SECRET", "unit-test-pass-secret")
    monkeypatch.setattr(config, "TURNSTILE_BYPASS_IPS", [])
    monkeypatch.setattr(smtpcheck, "enabled", lambda: True)
    monkeypatch.setattr(smtp.cooldown, "check", lambda t: None)

    class Res:
        def to_dict(self):
            return {"status": "ok", "data": {"enabled": True}}

    async def fake_check(host, port):
        return Res()
    monkeypatch.setattr(smtpcheck, "check", fake_check)


def hdr(token=None, with_pass=True):
    h = dict(VISITOR)
    if with_pass:
        h["X-Tools-Pass"] = turnstile.issue_pass(IP, UA)
    if token:
        h["X-Turnstile-Token"] = token
    return h


@pytest.fixture
def siteverify(monkeypatch):
    used = set()
    calls = []

    async def verify(token, ip):
        calls.append((token, ip))
        if token == "good" or (token.startswith("tok") and token not in used):
            used.add(token)
            return True
        return False
    monkeypatch.setattr(turnstile, "verify", verify)
    return calls


async def test_no_token_is_403(client, siteverify):
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr())
    assert r.status_code == 403 and r.json()["error"] == "turnstile_required" and r.json()["message"]


async def test_no_pass_is_still_pass_required(client, siteverify):
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr("good", with_pass=False))
    assert r.status_code == 403 and r.json() == {"error": "pass_required"}


async def test_valid_token_and_pass_proceeds(client, siteverify):
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr("good"))
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert siteverify == [("good", IP)]  # remoteip passed through


async def test_reused_or_invalid_token_is_403(client, siteverify, monkeypatch):
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr("tok1"))
    assert r.status_code == 200
    monkeypatch.setattr(smtp, "_cache", smtp.TTLCache(60))
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr("tok1"))
    assert r.status_code == 403 and r.json()["error"] == "turnstile_required"
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr("bogus"))
    assert r.status_code == 403


async def test_cloudflare_unreachable_fails_closed(client, monkeypatch):
    async def boom(token, ip):
        raise httpx.ConnectError("down")
    monkeypatch.setattr(turnstile, "verify", boom)
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr("good"))
    assert r.status_code == 503 and r.json()["error"] == "turnstile_unavailable"


async def test_bypass_ip_skips_token(client, siteverify, monkeypatch):
    monkeypatch.setattr(config, "TURNSTILE_BYPASS_IPS", ["93.184.215.0/24"])
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=hdr(with_pass=False))
    assert r.status_code == 200 and siteverify == []


async def test_sixth_call_in_window_is_429(client, siteverify):
    codes = []
    for i in range(6):
        codes.append((await client.post(f"{API}/smtp/check", json={"host": f"93.184.215.{20 + i}", "port": 25},
                                        headers=hdr(f"tok-n{i}"))).status_code)
    assert codes == [200] * 5 + [429]


async def test_rate_limit_is_per_network(client, siteverify):
    for i in range(5):
        await client.post(f"{API}/smtp/check", json={"host": f"93.184.215.{20 + i}", "port": 25}, headers=hdr(f"tok-m{i}"))
    other = {"X-Real-IP": "198.51.100.9", "User-Agent": UA, "X-Tools-Pass": turnstile.issue_pass("198.51.100.9", UA),
             "X-Turnstile-Token": "tok-other"}
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=other)
    assert r.status_code == 200


async def test_other_heavy_endpoints_only_need_the_pass(client, siteverify, monkeypatch):
    async def probe(ip, port):
        return {"port": port, "service": None, "state": "open", "ms": 5}
    monkeypatch.setattr(portcheck, "probe", probe)
    r = await client.post(f"{API}/ports/check", json={"port": 443}, headers=hdr())  # pass, no Turnstile token
    assert r.status_code == 200
    assert siteverify == []


async def test_smtp_disabled_default_needs_nothing(client, monkeypatch):
    monkeypatch.setattr(smtpcheck, "enabled", lambda: False)
    r = await client.post(f"{API}/smtp/check", json=BODY, headers=VISITOR)
    assert r.status_code == 200
