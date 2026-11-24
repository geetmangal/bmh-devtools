"""PeeringDB client: mapping, auth header, cache, 429 partial results, concurrency limit (offline)."""
import asyncio

from app.core import peeringdb
from app.core.httpjson import FetchError
from tests.test_bgp_fixtures import StubFetch, clean_bgp_state, pdb_routes  # noqa: F401

RATE = FetchError("upstream returned HTTP 429")


async def test_net_by_asn_maps_fields():
    r = await peeringdb.net_by_asn(13335, StubFetch(pdb_routes()))
    assert r["found"] and r["name"] == "Cloudflare" and r["policy"] == "Open" and r["irr_as_set"].endswith("AS-CLOUDFLARE")
    assert r["info_type"] == "Content" and r["traffic"] is None and r["website"] == "https://www.cloudflare.com"
    assert r["partial"] is False


async def test_net_not_found():
    r = await peeringdb.net_by_asn(64500, StubFetch(pdb_routes(net=[])))
    assert r["found"] is False and r["partial"] is False


async def test_api_key_header_only_when_set(monkeypatch):
    f = StubFetch(pdb_routes())
    await peeringdb.net_by_asn(13335, f)
    assert f.calls[0][2] == {}
    peeringdb.clear_cache()
    monkeypatch.setenv("PEERINGDB_API_KEY", "k3y")
    f2 = StubFetch(pdb_routes())
    await peeringdb.net_by_asn(13335, f2)
    assert f2.calls[0][2] == {"Authorization": "Api-Key k3y"}
    assert f2.calls[0][0].startswith("https://www.peeringdb.com/api/")


async def test_results_cached():
    f = StubFetch(pdb_routes())
    await peeringdb.net_by_asn(13335, f)
    await peeringdb.net_by_asn(13335, f)
    await peeringdb.ix_presence(13335, f)
    await peeringdb.ix_presence(13335, f)
    assert f.count("/api/net") == 1 and f.count("/api/netixlan") == 1


async def test_ix_presence_joins_city_and_sorts_by_speed():
    f = StubFetch(pdb_routes())
    r = await peeringdb.ix_presence(13335, f)
    assert r["count"] == 2 and r["unique_ix"] == 2 and not r["partial"]
    assert [x["name"] for x in r["ixs"]] == ["AMS-IX", "NIXI Mumbai"]
    assert (r["ixs"][0]["city"], r["ixs"][0]["country"]) == ("Amsterdam", "NL")
    assert r["ixs"][1]["ipaddr6"] is None and r["ixs"][0]["is_rs_peer"] is True
    assert f.params("/api/ix")[0] == {"id__in": "31,177"}


async def test_facilities():
    r = await peeringdb.facilities(13335, StubFetch(pdb_routes()))
    assert r["count"] == 2 and r["facilities"][0]["name"] == "Nxtra Mumbai"   # sorted by country (IN < NL)
    assert r["facilities"][1]["country"] == "NL"


async def test_429_returns_partial_with_note_and_is_not_cached():
    f = StubFetch({"/api/net": RATE})
    r = await peeringdb.net_by_asn(13335, f)
    assert r["partial"] is True and "rate limit" in r["notes"][0].lower() and r["found"] is None
    await peeringdb.net_by_asn(13335, f)
    assert f.count("/api/net") == 2                       # partial result was not cached
    r = await peeringdb.ix_presence(13335, StubFetch({"/api/netixlan": RATE}))
    assert r["partial"] and r["ixs"] == []
    r = await peeringdb.facilities(13335, StubFetch({"/api/netfac": RATE}))
    assert r["partial"] and r["facilities"] == []


async def test_429_on_ix_city_lookup_keeps_ports_without_cities():
    routes = pdb_routes()
    routes["/api/ix"] = RATE
    r = await peeringdb.ix_presence(13335, StubFetch(routes))
    assert r["partial"] is True and r["count"] == 2
    assert all(x["city"] is None for x in r["ixs"]) and r["notes"]


async def test_other_errors_raise():
    import pytest
    with pytest.raises(peeringdb.PeeringDBError):
        await peeringdb.net_by_asn(13335, StubFetch({"/api/net": FetchError("upstream returned HTTP 500")}))


async def test_at_most_two_requests_in_flight():
    active = peak = 0

    async def slow(_p):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return {"data": [], "meta": {}}

    f = StubFetch({"/api/net": slow})
    await asyncio.gather(*(peeringdb.net_by_asn(64500 + i, f) for i in range(8)))
    assert peak == 2 and f.count("/api/net") == 8
