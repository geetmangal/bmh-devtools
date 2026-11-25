"""Short result cache: TTL config, TTLCache.get_with_age and the `cache` field on cached endpoints."""
import time

import pytest

from app.api import bgp as bgp_api
from app.api import mail
from app.core import config, prefixdns
from app.core.cache import TTLCache
from app.core.mailcheck.resolver import FakeResolver
from tests.test_prefix_v3 import REAL, ptr_zone
from tests.test_toolbox_v2 import API, VISITOR, client, fresh, result, ts_on, with_pass  # noqa: F401 (fixtures)


# --- config + cache primitives ----------------------------------------------------------------------------
@pytest.mark.parametrize("raw,want", [(None, 60), ("30", 30), ("0", 0), ("-5", 0), ("9999", 300), ("abc", 60)])
def test_result_ttl_config(monkeypatch, raw, want):
    if raw is None:
        monkeypatch.delenv("BMH_TOOLS_RESULT_TTL", raising=False)
    else:
        monkeypatch.setenv("BMH_TOOLS_RESULT_TTL", raw)
    assert config._result_ttl() == want


def test_upstream_ttls_are_capped():
    from app.core import irr, ripestat
    cap = float(config.RESULT_CACHE_TTL)
    assert irr.TTL <= cap and max(ripestat.TTL_SHORT, ripestat.TTL_MID, ripestat.TTL_LONG) <= cap


def test_get_with_age(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    c = TTLCache(60)
    assert c.get_with_age("k") == (None, 0)
    c.set("k", {"a": 1})
    now[0] += 7.9
    assert c.get_with_age("k") == ({"a": 1}, 7)
    assert c.get("k") == {"a": 1}
    now[0] += 60
    assert c.get_with_age("k") == (None, 0) and c.get("k") is None


def test_zero_ttl_never_caches():
    c = TTLCache(0)
    c.set("k", 1)
    assert c.get_with_age("k") == (None, 0)


# --- endpoints ----------------------------------------------------------------------------------------------
async def test_mail_endpoint_cache_field(client, monkeypatch):
    calls = []

    async def fake(domain, *a, **k):
        calls.append(domain)
        return result("spf", domain)
    monkeypatch.setattr(mail.spf, "check", fake)
    first = (await client.post(f"{API}/mail/spf", json={"domain": "example.com"}, headers=VISITOR)).json()
    assert first["cache"] == {"hit": False, "age_s": 0, "ttl_s": config.RESULT_CACHE_TTL}
    second = (await client.post(f"{API}/mail/spf", json={"domain": "example.com"}, headers=VISITOR)).json()
    assert second["cache"]["hit"] is True and second["cache"]["age_s"] >= 0 and second["cache"]["ttl_s"] == config.RESULT_CACHE_TTL
    assert len(calls) == 1
    assert "cache" not in mail._cache.get("spf|example.com|")  # the stored dict is never mutated


async def test_prefix_endpoint_cache_field(client, monkeypatch, ts_on):
    n = []

    async def prefix_report(res):
        n.append(res)
        return {"prefix": "1.1.1.0/24", "queried": "1.1.1.0/24", "announced": True, "summary": "ok", "origins": [], "findings": []}
    monkeypatch.setattr(bgp_api.bgpview, "prefix_report", prefix_report)
    a = (await client.get(f"{API}/prefix/1.1.1.0/24", headers=with_pass())).json()
    assert a["cache"] == {"hit": False, "age_s": 0, "ttl_s": config.RESULT_CACHE_TTL}
    b = (await client.get(f"{API}/prefix/1.1.1.0/24", headers=with_pass())).json()
    assert b["cache"]["hit"] is True and len(n) == 1
    assert "cache" not in bgp_api._prefix_cache.get("1.1.1.0/24")


async def test_prefix_rdns_endpoint_cache_field(client, monkeypatch, ts_on):
    monkeypatch.setattr(prefixdns, "make_resolver", lambda: FakeResolver(ptr_zone()))
    monkeypatch.setattr(bgp_api, "_rdns_cache", TTLCache(60))
    a = (await client.post(f"{API}/prefix-rdns", json={"prefix": REAL, "block": 0}, headers=with_pass())).json()
    assert a["cache"] == {"hit": False, "age_s": 0, "ttl_s": config.RESULT_CACHE_TTL}
    b = (await client.post(f"{API}/prefix-rdns", json={"prefix": REAL, "block": 0}, headers=with_pass())).json()
    assert b["cache"]["hit"] is True and b["stats"] == a["stats"]
