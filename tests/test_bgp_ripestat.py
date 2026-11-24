"""RIPEstat wrappers: parsing, trimming, caching, error handling (offline, stubbed fetch)."""
import pytest

from app.core import ripestat
from app.core.httpjson import FetchError
from tests.test_bgp_fixtures import (PFX, StubFetch, asn_routes, clean_bgp_state, lg_peer, neighbour, ok,  # noqa: F401
                                     ripe_routes, vis_entry)


async def test_as_overview_trimmed_and_sourceapp_sent():
    f = StubFetch(asn_routes())
    r = await ripestat.as_overview("AS13335", f)
    assert r == {"asn": 13335, "holder": "CLOUDFLARENET - Cloudflare, Inc.", "name": "Cloudflare, Inc.", "announced": True,
                 "block": "Assigned by ARIN"}
    assert f.params("as-overview/data.json")[0] == {"resource": "AS13335", "sourceapp": "bookmyhost-tools"}


async def test_sourceapp_env_override(monkeypatch):
    monkeypatch.setenv("RIPESTAT_SOURCEAPP", "my-app")
    f = StubFetch(asn_routes())
    await ripestat.as_overview(13335, f)
    assert f.params("as-overview/data.json")[0]["sourceapp"] == "my-app"


async def test_second_call_is_served_from_cache():
    f = StubFetch(asn_routes())
    await ripestat.as_overview(13335, f)
    await ripestat.as_overview("AS13335", f)
    assert f.count("as-overview/data.json") == 1


async def test_status_not_ok_and_fetch_errors_raise_ripestat_error():
    bad = StubFetch({"as-overview/data.json": {"status": "error", "messages": [["error", "Resource is invalid"]], "data": {}}})
    with pytest.raises(ripestat.RipeStatError, match="Resource is invalid"):
        await ripestat.as_overview(1, bad)
    down = StubFetch({"as-overview/data.json": FetchError("upstream request failed: ConnectTimeout")})
    with pytest.raises(ripestat.RipeStatError):
        await ripestat.as_overview(2, down)
    nodata = StubFetch({"as-overview/data.json": {"status": "ok", "data": None}})
    with pytest.raises(ripestat.RipeStatError):
        await ripestat.as_overview(3, nodata)


async def test_errors_are_not_cached():
    f = StubFetch({"as-overview/data.json": FetchError("boom")})
    for _ in range(2):
        with pytest.raises(ripestat.RipeStatError):
            await ripestat.as_overview(5, f)
    assert f.count("as-overview/data.json") == 2


def test_invalid_inputs():
    for bad in ("ASX", "", "-1", "99999999999", None):
        with pytest.raises(ValueError):
            ripestat.parse_asn(bad)
    with pytest.raises(ValueError):
        ripestat.norm_resource("not-an-ip")
    assert ripestat.norm_resource("1.1.1.5/24") == "1.1.1.0/24"
    assert ripestat.norm_resource("as13335") == "AS13335"


def test_neighbour_classification_left_right_uncertain_sorted_by_power():
    raw = [neighbour(1, "left", 10), neighbour(2, "left", 90), neighbour(3, "right", 5), neighbour(4, "uncertain", 7),
           neighbour(5, "weird", 1), {"asn": "bad"}, neighbour(6, "right", 50)]
    c = ripestat.classify_neighbours(raw)
    assert [n["asn"] for n in c["upstreams"]] == [2, 1]
    assert [n["asn"] for n in c["downstreams"]] == [6, 3]
    assert [n["asn"] for n in c["uncertain"]] == [4, 5]
    assert c["upstreams"][0]["role"] == "upstream" and c["downstreams"][0]["role"] == "downstream"


async def test_asn_neighbours_counts_and_lists():
    r = await ripestat.asn_neighbours(13335, StubFetch(asn_routes()))
    assert r["counts"] == {"left": 3, "right": 2, "uncertain": 1, "unique": 6}
    assert [n["asn"] for n in r["upstreams"]] == [3356, 174, 1299]
    assert r["upstreams"][0]["power"] == 900


async def test_announced_prefixes_families_and_order():
    r = await ripestat.announced_prefixes(13335, StubFetch(asn_routes()))
    assert (r["count"], r["v4"], r["v6"]) == (5, 4, 1)
    assert r["prefixes"][0]["prefix"] == "104.16.0.0/13"          # shortest v4 first
    assert r["prefixes"][-1]["family"] == 6
    assert r["prefixes"][0]["first_seen"] == "2026-11-10T08:00:00"


@pytest.mark.parametrize("p,state,reason", [("1.1.1.0/24", "valid", None), ("104.16.0.0/13", "unknown", None),
                                            ("172.64.0.0/13", "invalid", "asn")])
async def test_rpki_validation_states(p, state, reason):
    r = await ripestat.rpki_validation(13335, p, StubFetch(asn_routes()))
    assert (r["state"], r["reason"]) == (state, reason)
    assert r["prefix"] == p


async def test_rpki_invalid_length_reason():
    f = StubFetch({"rpki-validation/data.json": ok({"status": "invalid_length", "validating_roas": [
        {"origin": "13335", "prefix": "1.1.0.0/16", "validity": "invalid_length", "max_length": 16}], "validator": "routinator"})})
    r = await ripestat.rpki_validation(13335, "1.1.1.0/24", f)
    assert (r["state"], r["reason"]) == ("invalid", "length")
    assert r["roas"][0]["max_length"] == 16


async def test_routing_status_trims_origins_and_specifics():
    f = StubFetch(ripe_routes(origins=(13335, 64500), more=[{"prefix": "1.1.1.0/25", "origin": 64511}, "1.1.1.128/25"],
                              less=[{"prefix": "1.1.0.0/16", "origin": 64600}]))
    r = await ripestat.routing_status(PFX, f)
    assert r["origins"] == [13335, 64500]
    assert r["visibility"]["v4"] == {"seeing": 278, "total": 279, "pct": 99.6}
    assert r["visibility"]["v6"]["pct"] is None
    assert r["more_specifics"] == [{"prefix": "1.1.1.0/25", "origin": 64511}, {"prefix": "1.1.1.128/25", "origin": None}]
    assert r["less_specifics"][0]["origin"] == 64600


async def test_visibility_seen_total_per_collector_and_family():
    f = StubFetch(ripe_routes())
    r = await ripestat.visibility(PFX, f)
    by = {c["id"]: c for c in r["collectors"]}
    assert (by["rrc00"]["seen"], by["rrc00"]["total"], by["rrc00"]["is_seen"]) == (40, 40, True)
    assert (by["rrc01"]["seen"], by["rrc01"]["total"]) == (63, 70)
    assert by["rrc12"]["seen"] == 0 and by["rrc12"]["is_seen"] is False
    assert by["rrc02"]["total"] == 0
    assert by["rrc01"]["lat"] == 51.4969
    r6 = await ripestat.visibility("2606:4700::/32", StubFetch({"visibility/data.json": ok({"visibilities": [vis_entry("RRC00", 9, v6_total=30)]})}))
    assert r6["family"] == 6 and r6["collectors"][0]["total"] == 30


async def test_prefix_overview_and_network_info():
    f = StubFetch(ripe_routes())
    ov = await ripestat.prefix_overview(PFX, f)
    assert ov["announced"] and ov["asns"][0]["asn"] == 13335
    ni = await ripestat.network_info("1.1.1.1", f)
    assert ni == {"ip": "1.1.1.1", "prefix": PFX, "asns": [13335]}


async def test_looking_glass_paths_parsed_with_as_set_braces():
    f = StubFetch({"looking-glass/data.json": ok({"rrcs": [{"rrc": "RRC01", "location": "London, GB", "peers": [
        lg_peer("15692 13335"), lg_peer("1 2 {3,4}"), {"as_path": "", "peer": "x"}]}]})})
    r = await ripestat.looking_glass(PFX, f)
    assert r["rrcs"][0]["rrc"] == "rrc01"
    paths = [p["as_path"] for p in r["rrcs"][0]["peers"]]
    assert paths == [[15692, 13335], [1, 2, 3, 4]]          # empty path dropped
    assert r["rrcs"][0]["peers"][0]["origin_asn"] == 13335


async def test_routing_history_timeline_sorted_and_origins():
    hist = [{"origin": "64500", "prefixes": [{"prefix": PFX, "timelines": [{"starttime": "2026-11-15T00:00:00", "endtime": "2026-11-24T00:00:00", "full_peers_seeing": 10}]}]},
            {"origin": "13335", "prefixes": [{"prefix": PFX, "timelines": [{"starttime": "2026-10-27T00:00:00", "endtime": "2026-11-14T23:59:59", "full_peers_seeing": 320.0}]}]}]
    r = await ripestat.routing_history(PFX, fetch=StubFetch(ripe_routes(history=hist)))
    assert [t["origin"] for t in r["timeline"]] == [13335, 64500]
    assert {o["origin"] for o in r["origins"]} == {13335, 64500}
    assert r["timeline"][0]["peers"] == 320


async def test_geoloc_known_and_anycast_unknown():
    known = StubFetch({"maxmind-geo-lite/data.json": ok({"located_resources": [{"resource": "8.8.8.8/32", "locations": [
        {"country": "US", "city": "", "resources": ["8.8.8.0/23"], "latitude": 37.751, "longitude": -97.822, "covered_percentage": 100.0}]}]})})
    g = await ripestat.geoloc("8.8.8.8", known)
    assert g["known"] and g["country"] == "US" and g["lat"] == 37.751 and g["city"] is None
    anycast = StubFetch({"maxmind-geo-lite/data.json": ok({"located_resources": [{"resource": "1.1.1.1/32", "locations": [
        {"country": "?", "city": "", "resources": ["1.1.1.0/24"], "latitude": 0.0, "longitude": 0.0, "covered_percentage": 100.0}]}]})})
    g = await ripestat.geoloc("1.1.1.1", anycast)
    assert g["known"] is False and g["lat"] is None and g["country"] is None


async def test_whois_and_rir_country():
    w = StubFetch({"whois/data.json": ok({"records": [[{"key": "aut-num", "value": "AS13335"}, {"key": "as-name", "value": "CLOUDFLARENET"},
                                                      {"key": "country", "value": "US"}, {"key": "noise", "value": "x"}]], "authorities": ["arin"]})})
    r = await ripestat.whois_asn(13335, w)
    assert r["as_name"] == "CLOUDFLARENET" and r["country"] == "US" and len(r["records"]) == 3
    c = StubFetch({"rir-stats-country/data.json": ok({"located_resources": [{"resource": "13335", "location": "US"}]})})
    assert (await ripestat.rir_stats_country(13335, c))["country"] == "US"
    cc = StubFetch({"rir-stats-country/data.json": ok({"resources": {"asn": ["1", "2"], "ipv4": ["1.0.0.0/8"], "ipv6": []}})})
    r = await ripestat.rir_stats_country("in", cc)
    assert r["country"] == "IN" and r["counts"]["asn"] == 2
