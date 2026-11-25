"""BGP Prefix Lookup v3 backend (offline): overview / connectivity / validation blocks, IRR verdicts, ROA max-length,
whois parsing + geofeed, PTR sweep, and the /prefix-whois + /prefix-rdns endpoints."""
import asyncio
import json
import time
from pathlib import Path

import pytest

from app.api import bgp as bgp_api
from app.core import bgpview, cooldown, irr, pathgraph, prefixdns, prefixwhois, ratelimit, ripestat
from app.core.httpjson import FetchError
from app.core.mailcheck.resolver import FakeResolver
from tests.test_bgp_fixtures import (PFX, StubFetch, clean_bgp_state, irr_entry, lg_peer, ok, ripe_routes,  # noqa: F401
                                     whois_data, kv)
from tests.test_toolbox_v2 import API, VISITOR, client, fresh, ts_on, with_pass  # noqa: F401

FIX = Path(__file__).parent / "fixtures" / "prefix_v3"
REAL = "160.22.108.0/24"


def fid(report, id_):
    return next((f for f in report["findings"] if f["id"] == id_), None)


@pytest.fixture(autouse=True)
def v3_state(monkeypatch):
    irr.clear_cache()
    monkeypatch.setattr(bgp_api, "_light_bucket", ratelimit.TokenBucket(1000, 1000))
    monkeypatch.setattr(bgp_api, "_rdns_bucket", ratelimit.TokenBucket(1000, 1000))
    for name in ("_whois_cache", "_rdns_cache"):
        monkeypatch.setattr(bgp_api, name, type(getattr(bgp_api, name))(60))
    yield


# --- connectivity graph -----------------------------------------------------------------------------------
def lg_of(paths):
    return {"rrcs": [{"rrc": "rrc00", "location": "x", "peers": [
        {"peer": f"192.0.2.{i}", "origin_asn": p[-1], "as_path": p, "prefix": PFX, "last_updated": None} for i, p in enumerate(paths)]}]}


PATHS = [[100, 3356, 13335, 152523], [100, 3356, 13335, 152523], [101, 13335, 152523, 152523, 152523],
         [3356, 13335, 152523], [102, 6939, 13335, 152523]]


def test_graph_depth_roles_share_tier1():
    c = pathgraph.build(lg_of(PATHS), {152523: "Origin Net", 13335: "Cloudflare"})
    nodes = {n["asn"]: n for n in c["graph"]["nodes"]}
    assert nodes[152523]["role"] == "origin" and nodes[152523]["depth"] == 0 and nodes[152523]["paths"] == 5
    assert nodes[152523]["name"] == "Origin Net" and nodes[152523]["id"] == "AS152523"
    assert nodes[13335]["role"] == "upstream" and nodes[13335]["depth"] == 1 and nodes[13335]["share"] == 1.0
    assert nodes[3356]["tier1"] is True and nodes[3356]["role"] == "peer" and nodes[3356]["depth"] == 2     # first AS on a path -> collector peer
    assert nodes[6939]["role"] == "transit" and nodes[6939]["depth"] == 2 and nodes[6939]["tier1"] is False
    assert nodes[100]["role"] == "peer" and nodes[100]["depth"] == 3 and nodes[100]["paths"] == 2 and nodes[100]["share"] == 0.4
    edges = {(e["from"], e["to"]): e["count"] for e in c["graph"]["edges"]}
    assert edges[("AS13335", "AS152523")] == 5 and edges[("AS3356", "AS13335")] == 3       # direction: towards the origin
    assert ("AS152523", "AS152523") not in edges                                           # prepending collapsed
    assert c["upstreams"] == [{"asn": 13335, "name": "Cloudflare", "paths": 5, "share": 1.0, "tier1": False}]
    assert c["paths_total"] == 5 and c["collector_peers"] == 5


def test_path_length_and_prepending():
    c = pathgraph.build(lg_of(PATHS))
    assert c["path_length"] == {"min": 3, "median": 4, "max": 4, "hist": {"3": 2, "4": 3}}
    assert c["prepending"] == [{"asn": 152523, "max_repeat": 3, "paths": 1}]


def test_upstreams_sorted_by_share_and_multi_upstream():
    paths = [[1, 174, 64500]] * 3 + [[2, 3356, 64500]] + [[3, 6939, 64500]] * 2
    c = pathgraph.build(lg_of(paths))
    assert [(u["asn"], u["paths"], u["tier1"]) for u in c["upstreams"]] == [(174, 3, True), (6939, 2, False), (3356, 1, True)]
    assert c["upstreams"][0]["share"] == 0.5


def test_graph_node_cap_keeps_origin_and_busiest():
    paths = [[1000 + i, 2000 + i, 13335, 64500] for i in range(80)] + [[999, 13335, 64500]] * 3
    c = pathgraph.build(lg_of(paths))
    ids = {n["asn"] for n in c["graph"]["nodes"]}
    assert len(ids) == pathgraph.MAX_NODES and {64500, 13335} <= ids
    node_ids = {n["id"] for n in c["graph"]["nodes"]}
    assert all(e["from"] in node_ids and e["to"] in node_ids for e in c["graph"]["edges"])


def test_graph_empty_and_origin_only():
    assert pathgraph.build({"rrcs": []}) is None and pathgraph.build(None) is None
    c = pathgraph.build(lg_of([[64500]]))
    assert c["graph"]["edges"] == [] and c["upstreams"] == [] and c["path_length"]["min"] == 1


# --- IRR --------------------------------------------------------------------------------------------------
def real_mismatch_entries():
    return json.loads((FIX / "irr_explorer_160.22.108.0_24_stale.json").read_text())


def test_irr_build_mismatch_real_shape():
    b = irr.build(real_mismatch_entries(), REAL, [152523])
    assert b["verdict"] == "mismatch" and b["available"] is True and b["sources"] == ["APNIC"]
    exact = [o for o in b["objects"] if o["exact"]]
    assert [(o["source"], o["asn"], o["matches_bgp"]) for o in exact] == [("APNIC", 151734, False)]
    assert b["rpki_routes"] == [{"prefix": "160.22.108.0/23", "asn": 151734, "max_length": 24},
                                {"prefix": "160.22.108.0/23", "asn": 152523, "max_length": 24}]
    assert b["category"] == "warning" and b["messages"][0]["category"] == "warning" and b["rir"] == "APNIC"
    assert "origin:         AS151734" in exact[0]["rpsl"]


async def test_prefix_report_irr_mismatch_finding():
    routes = ripe_routes(prefix=REAL, origins=(152523,), irr=real_mismatch_entries())
    r = await bgpview.prefix_report(REAL, fetch=StubFetch(routes))
    f = fid(r, "irr-mismatch")
    assert f and f["status"] == "warn" and f["meaning"] and f["fix"] and "AS152523" in f["title"] and "AS151734" in f["meaning"]
    assert f["details"]["irr_origins"] == [151734] and f["details"]["bgp_origins"] == [152523]
    assert r["validation"]["summary"] == {"rpki": "valid", "irr": "mismatch"} and r["status"] == "warn"
    assert fid(r, "irr-match") is None and fid(r, "irr-missing") is None
    assert r["validation"]["irr"]["objects"][0]["matches_bgp"] is False
    assert "verdict" not in r["validation"]["irr"] and "rir" not in r["validation"]["irr"]


async def test_prefix_report_irr_match_and_missing():
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes()))
    assert fid(r, "irr-match")["status"] == "pass" and r["validation"]["summary"]["irr"] == "match"
    assert r["validation"]["irr"]["objects"][0]["exact"] is True and r["missing"] == []
    irr.clear_cache()
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes(irr=[irr_entry(PFX, objects=[], bgp=[13335])])))
    f = fid(r, "irr-missing")
    assert f["status"] == "warn" and f["meaning"] and f["fix"] and r["validation"]["summary"]["irr"] == "missing"
    assert r["validation"]["irr"]["available"] is True and r["validation"]["irr"]["objects"] == []


def test_irr_covering_object_counts_and_moas():
    entries = [irr_entry("1.1.0.0/16", objects=[("RADB", 13335)], bgp=[]), irr_entry("1.1.1.0/24", objects=[], bgp=[13335])]
    b = irr.build(entries, PFX, [13335])
    assert b["verdict"] == "match" and b["objects"][0]["exact"] is False and b["objects"][0]["prefix"] == "1.1.0.0/16"
    moas = irr.build([irr_entry(PFX, objects=[("RIPE", 13335)])], PFX, [13335, 64500])
    assert moas["verdict"] == "mismatch"                      # one of two origins has no route object
    assert irr.build([irr_entry("1.1.1.0/25", objects=[("RIPE", 1)])], PFX, [13335])["verdict"] == "missing"   # more-specific is ignored


async def test_irr_source_failure_goes_to_missing_not_error():
    routes = ripe_routes()
    routes["/api/prefixes/prefix/" + PFX] = FetchError("upstream request failed: ReadTimeout")
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    assert r["missing"] == ["irr"] and "irr" in r["errors"] and r["partial"] is True
    assert r["validation"]["irr"]["available"] is False and r["validation"]["summary"]["irr"] == "unknown"
    assert fid(r, "irr-mismatch") is None and fid(r, "irr-missing") is None and r["connectivity"] is not None


async def test_whois_failure_leaves_overview_partial_or_null():
    routes = ripe_routes()
    routes["whois/data.json"] = FetchError("boom")
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    assert r["missing"] == ["whois"] and r["overview"]["holder"] is None and r["overview"]["abuse_email"] == "abuse@example.net"
    assert r["overview"]["size"]["addresses"] == 256
    irr.clear_cache()
    ripestat.clear_caches()
    routes["abuse-contact-finder/data.json"] = FetchError("boom")
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    assert r["overview"] is None and "whois" in r["missing"]


# --- ROA max length ---------------------------------------------------------------------------------------
def rpki_with_maxlen(roa_prefix, maxlen):
    def route(p):
        return ok({"resource": p["resource"], "prefix": p["prefix"], "status": "valid", "validator": "routinator",
                   "validating_roas": [{"origin": "13335", "prefix": roa_prefix, "max_length": str(maxlen), "validity": "valid"}]})
    return route


async def test_roa_maxlength_loose():
    routes = ripe_routes(prefix="1.1.0.0/24")
    routes["rpki-validation/data.json"] = rpki_with_maxlen("1.1.0.0/16", 28)
    r = await bgpview.prefix_report("1.1.0.0/24", fetch=StubFetch(routes))
    f = fid(r, "roa-maxlength-loose")
    assert f and f["status"] == "warn" and "/28" in f["title"] and "/24" in f["title"] and f["meaning"] and f["fix"]
    assert r["validation"]["rpki"][0]["maxlength_loose"] is True and r["validation"]["rpki"][0]["roas"][0]["max_length"] == 28
    assert r["validation"]["summary"]["rpki"] == "valid"


async def test_roa_maxlength_exact_and_slightly_loose():
    routes = ripe_routes(prefix="1.1.0.0/24")
    routes["rpki-validation/data.json"] = rpki_with_maxlen("1.1.0.0/23", 24)
    r = await bgpview.prefix_report("1.1.0.0/24", fetch=StubFetch(routes))
    assert fid(r, "roa-maxlength-loose") is None and r["validation"]["rpki"][0]["maxlength_loose"] is False
    routes = ripe_routes(prefix="1.1.0.0/23")
    routes["rpki-validation/data.json"] = rpki_with_maxlen("1.1.0.0/23", 24)
    r = await bgpview.prefix_report("1.1.0.0/23", fetch=StubFetch(routes))
    assert fid(r, "roa-maxlength-loose")["status"] == "info"


async def test_validation_rpki_invalid_and_unknown_summary():
    routes = ripe_routes(rpki={(13335, PFX): "invalid_asn"})
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    assert r["validation"]["summary"]["rpki"] == "invalid" and r["validation"]["rpki"][0]["state"] == "invalid"
    irr.clear_cache()
    ripestat.clear_caches()
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes(rpki={(13335, PFX): "unknown"})))
    assert r["validation"]["summary"]["rpki"] == "unknown" and r["validation"]["rpki"][0]["roas"] == []


# --- report: overview + connectivity ----------------------------------------------------------------------
async def test_overview_block():
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes()))
    o = r["overview"]
    assert (o["rir"], o["country"], o["netname"], o["holder"], o["inetnum"]) == ("APNIC", "IN", "TESTNET", "TEST HOLDER PRIVATE LIMITED", PFX)
    assert o["reg_status"] == "ASSIGNED PORTABLE" and "provider-independent" in o["reg_status_meaning"]
    assert o["size"] == {"addresses": 256, "slash24s": 1, "slash48s": None} and o["abuse_email"] == "abuse@example.net"
    assert o["registered"] is None and o["age_days"] is None


async def test_connectivity_in_report_with_names_from_peeringdb():
    routes = ripe_routes(lg=[{"rrc": "RRC01", "location": "London", "peers": [
        {"asn_origin": "13335", "as_path": "15692 3356 13335", "peer": "5.57.80.1", "prefix": PFX},
        {"asn_origin": "13335", "as_path": "8218 13335 13335", "peer": "5.57.80.2", "prefix": PFX}]}])
    routes["/api/net"] = {"data": [{"asn": 13335, "name": "Cloudflare"}, {"asn": 3356, "name": "Lumen"}], "meta": {}}
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    c = r["connectivity"]
    by = {n["asn"]: n for n in c["graph"]["nodes"]}
    assert by[13335]["role"] == "origin" and by[13335]["name"] == "Net 13335" and by[3356]["name"] == "Lumen" and by[3356]["tier1"] is True
    assert by[8218]["role"] == "upstream" and by[15692]["role"] == "peer" and c["paths_total"] == 2 and c["upstreams"][0]["asn"] == 3356
    assert c["prepending"] == [{"asn": 13335, "max_repeat": 2, "paths": 1}]


async def test_connectivity_null_when_looking_glass_fails():
    routes = ripe_routes()
    routes["looking-glass/data.json"] = FetchError("x")
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    assert r["connectivity"] is None and "as_paths" in r["missing"] and r["validation"] is not None


# --- whois ------------------------------------------------------------------------------------------------
def test_meanings_table_covers_registry_statuses():
    for s in ("ASSIGNED PORTABLE", "ALLOCATED PORTABLE", "ASSIGNED NON-PORTABLE", "ALLOCATED PA", "ASSIGNED PA", "ASSIGNED PI",
              "LEGACY", "SUB-ALLOCATED PA", "ALLOCATED-BY-RIR", "Direct Allocation", "reassigned"):
        assert prefixwhois.status_meaning(s), s
    assert prefixwhois.status_meaning("WEIRD") is None and prefixwhois.status_meaning(None) is None
    assert prefixwhois.key_meaning("inetnum") and prefixwhois.key_meaning("MNT-BY") and prefixwhois.key_meaning("nope") is None
    assert prefixwhois.key_meaning("status", "LEGACY") == prefixwhois.status_meaning("LEGACY")
    assert json.loads((Path(prefixwhois._MEANINGS)).read_text())["keys"]


def test_parse_records_adds_meanings():
    data = {"records": [[{"key": "inetnum", "value": PFX}, {"key": "status", "value": "ASSIGNED PA"}, {"key": "x-odd", "value": "1"}]],
            "irr_records": [[{"key": "route", "value": PFX}]], "authorities": ["ripe"]}
    recs, irr_recs, auth = prefixwhois.parse_records(data)
    assert recs[0][0] == {"key": "inetnum", "value": PFX, "meaning": prefixwhois.key_meaning("inetnum")}
    assert "provider" in recs[0][1]["meaning"] and recs[0][2]["meaning"] is None
    assert irr_recs == [[{"key": "route", "value": PFX}]] and auth == ["ripe"]


CSV = """# self-published geofeed
1.1.1.0/24,IN,IN-DL,New Delhi,
1.1.2.0/24,US,US-CA,San Jose,95101
1.1.0.0/16,IN,IN-MH,Mumbai,
2001:db8::/32,DE,,Berlin,
not-a-prefix,XX,,,
1.1.1.128/25,in,IN-DL,Delhi,110001
"""


def test_geofeed_overlap_filter():
    rows = prefixwhois.parse_geofeed(CSV, "1.1.1.0/24")
    assert [r["prefix"] for r in rows] == ["1.1.1.0/24", "1.1.0.0/16", "1.1.1.128/25"]        # only rows overlapping this prefix
    assert rows[0] == {"prefix": "1.1.1.0/24", "country": "IN", "region": "IN-DL", "city": "New Delhi", "zip": ""}
    assert rows[2]["country"] == "IN"
    many = "\n".join(f"10.{i}.0.0/16,IN,,x," for i in range(50))
    assert len(prefixwhois.parse_geofeed(many, "10.0.0.0/8")) == prefixwhois.GEOFEED_MAX_ROWS


@pytest.mark.parametrize("url", ["https://127.0.0.1/geofeed.csv", "https://localhost/g.csv", "https://10.0.0.5/g.csv",
                                 "https://[::1]/g.csv", "http://example.com/g.csv", "https://user:pw@example.com/g.csv",
                                 "https://169.254.169.254/latest/meta-data"])
async def test_geofeed_rejects_private_and_non_https_urls(url):
    g = await prefixwhois.geofeed(url, PFX)       # real fetcher: the guard refuses before any connection is made
    assert g["rows"] == [] and g["error"] and g["url"] == url


async def test_whois_report_with_geofeed_and_abuse():
    seen = {}

    async def text_fetch(url, params=None, timeout=5.0, headers=None, max_bytes=0):
        seen.update(url=url, timeout=timeout, max_bytes=max_bytes)
        return CSV

    out = await prefixwhois.report(PFX, fetch=StubFetch(ripe_routes()), text_fetch=text_fetch)
    assert seen == {"url": "https://geo.example.net/geofeed.csv", "timeout": 5.0, "max_bytes": 512 * 1024}
    assert out["prefix"] == PFX and out["authorities"] == ["apnic"] and out["abuse_email"] == "abuse@example.net"
    assert out["records"][0][0]["key"] == "inetnum" and out["irr_records"][0][0] == {"key": "route", "value": PFX}
    assert out["geofeed"]["error"] is None and len(out["geofeed"]["rows"]) == 3 and out["geofeed"]["url"].startswith("https://")
    assert "inetnum: " + PFX in out["raw"] and "route: " + PFX in out["raw"] and out["fetched_at"].endswith("Z")


async def test_whois_report_geofeed_error_and_absent_and_rfc9632_remark():
    async def bad(*a, **k):
        raise FetchError("upstream returned HTTP 404")
    out = await prefixwhois.report(PFX, fetch=StubFetch(ripe_routes()), text_fetch=bad)
    assert out["geofeed"] == {"url": "https://geo.example.net/geofeed.csv", "rows": [], "error": "upstream returned HTTP 404"}
    rec = kv([("inetnum", PFX), ("remarks", "Geofeed https://isp.example/feed.csv"), ("source", "RIPE")])
    w = {"records": [rec], "irr_records": [], "authorities": ["ripe"], "resource": PFX}
    ripestat.clear_caches()
    out = await prefixwhois.report(PFX, fetch=StubFetch(ripe_routes(whois=w)), text_fetch=bad)
    assert out["geofeed"]["url"] == "https://isp.example/feed.csv"
    w2 = {"records": [kv([("inetnum", PFX), ("source", "RIPE")])], "irr_records": [], "authorities": ["ripe"], "resource": PFX}
    ripestat.clear_caches()
    out = await prefixwhois.report(PFX, fetch=StubFetch(ripe_routes(whois=w2)), text_fetch=bad)
    assert out["geofeed"] is None and out["abuse_email"] == "abuse@example.net"


async def test_whois_report_abuse_failure_is_optional():
    routes = ripe_routes()
    routes["abuse-contact-finder/data.json"] = FetchError("x")
    out = await prefixwhois.report(PFX, fetch=StubFetch(routes), text_fetch=lambda *a, **k: asyncio.sleep(0, CSV))
    assert out["abuse_email"] is None and out["records"]


def test_overview_arin_style_keys():
    recs = [kv([("NetRange", "8.8.8.0 - 8.8.8.255"), ("CIDR", "8.8.8.0/24"), ("NetName", "GOGL"), ("OrgName", "Google LLC"),
                ("NetType", "Direct Allocation"), ("RegDate", "2014-03-14"), ("Country", "US")])]
    parsed, _i, _a = prefixwhois.parse_records({"records": recs})
    f = prefixwhois.overview_fields(parsed, ["arin"])
    assert (f["rir"], f["holder"], f["netname"], f["country"], f["inetnum"]) == ("ARIN", "Google LLC", "GOGL", "US", "8.8.8.0 - 8.8.8.255")
    assert f["reg_status"] == "Direct Allocation" and f["reg_status_meaning"] and f["registered"] == "2014-03-14"
    import datetime as dt
    assert prefixwhois.age_days("2014-03-14", dt.date(2015, 3, 14)) == 365 and prefixwhois.age_days("junk") is None


# --- PTR sweep --------------------------------------------------------------------------------------------
def ptr_zone():
    z = {"108.22.160.in-addr.arpa/NS": ["ns1.example.com", "ns2.example.com"], "108.22.160.in-addr.arpa/DS": ["12345 13 2 ABCD"],
         "ns1.example.com/A": ["192.0.2.1"], "ns2.example.com/AAAA": ["2001:db8::2"]}
    z["1.108.22.160.in-addr.arpa/PTR"] = ["mail.example.com"]
    z["mail.example.com/A"] = ["160.22.108.1"]                           # FCrDNS ok
    z["2.108.22.160.in-addr.arpa/PTR"] = ["spoof.example.com"]
    z["spoof.example.com/A"] = ["9.9.9.9"]                               # forward points elsewhere: fcrdns false
    z["3.108.22.160.in-addr.arpa/PTR"] = ["160-22-108-3.static.isp.net"]
    z["160-22-108-3.static.isp.net/A"] = ["160.22.108.3"]                # auto-generated but confirmed
    z["4.108.22.160.in-addr.arpa/PTR"] = ["gone.example.com"]            # forward name does not exist: false
    z["5.108.22.160.in-addr.arpa/PTR"] = ["slow.example.com"]
    z["slow.example.com/A"] = "TIMEOUT"                                  # unknown: null
    z["6.108.22.160.in-addr.arpa/PTR"] = ["6.108.22.160.dyn.isp.net"]    # reversed octets heuristic
    z["gone.example.com/TXT"] = ["x"]
    return z


def test_auto_heuristic():
    f = prefixdns.looks_auto
    assert f("160-22-108-3.static.isp.net", "160.22.108.3") and f("ip-160-22-108-3.x.net", "160.22.108.3")
    assert f("3.108.22.160.in-addr.arpa.isp.net", "160.22.108.3") and f("160.22.108.3.example.com", "160.22.108.3")
    assert f("host-a0166c03.example.com", "160.22.108.3") and f("2685824003.example.com", "160.22.108.3")
    assert f("ip-9-9-9-9.example.com", "160.22.108.3")                    # ip-like label
    assert not f("mail.example.com", "160.22.108.3") and not f("mx1-160.example.com", "160.22.108.3")
    assert not f("160-22-108.example.com", "160.22.108.3")                # three octets only: not a full IP


async def test_ptr_report_fcrdns_auto_and_delegation():
    rep = await prefixdns.report(REAL, 0, FakeResolver(ptr_zone()))
    assert rep["family"] == 4 and rep["block"] == 0 and rep["blocks"] == 1 and rep["base"] == REAL and len(rep["rows"]) == 256
    assert rep["delegations"] == [{"zone": "108.22.160.in-addr.arpa", "ns": ["ns1.example.com", "ns2.example.com"], "ds": True, "ns_problems": []}]
    rows = {r["ip"]: r for r in rep["rows"]}
    assert rows["160.22.108.1"] == {"ip": "160.22.108.1", "ptr": "mail.example.com", "fcrdns": True, "auto": False}
    assert rows["160.22.108.2"]["fcrdns"] is False and rows["160.22.108.4"]["fcrdns"] is False
    assert rows["160.22.108.3"]["auto"] is True and rows["160.22.108.3"]["fcrdns"] is True
    assert rows["160.22.108.5"]["ptr"] == "slow.example.com" and rows["160.22.108.5"]["fcrdns"] is None
    assert rows["160.22.108.6"]["auto"] is True and rows["160.22.108.7"] == {"ip": "160.22.108.7", "ptr": None, "fcrdns": None, "auto": False}
    assert rep["stats"] == {"scanned": 256, "with_ptr": 6, "fcrdns_ok": 2, "auto_generated": 2}
    assert rep["partial"] is False and rep["note"] is None


async def test_ptr_blocks_and_small_prefixes():
    r = FakeResolver({"109.22.160.in-addr.arpa/NS": ["ns.example.com"], "109.22.160.in-addr.arpa/DS": "NXDOMAIN", "ns.example.com/A": ["192.0.2.9"]})
    rep = await prefixdns.report("160.22.108.0/23", 1, r)
    assert rep["blocks"] == 2 and rep["block"] == 1 and rep["base"] == "160.22.109.0/24" and rep["rows"][0]["ip"] == "160.22.109.0"
    assert rep["delegations"] == [{"zone": "109.22.160.in-addr.arpa", "ns": ["ns.example.com"], "ds": False, "ns_problems": []}]
    with pytest.raises(ValueError):
        await prefixdns.report("160.22.108.0/23", 2, r)
    small = await prefixdns.report("160.22.108.64/26", 0, FakeResolver())
    assert len(small["rows"]) == 64 and small["rows"][0]["ip"] == "160.22.108.64" and small["base"] == "160.22.108.0/24"
    assert small["delegations"] == [] and "smaller than a /24" in small["note"]
    assert prefixdns.block_count(__import__("ipaddress").ip_network("10.0.0.0/16")) == 256


async def test_ptr_delegation_falls_back_to_parent_zone():
    r = FakeResolver({"22.160.in-addr.arpa/NS": ["ns.parent.example"], "ns.parent.example/A": ["192.0.2.7"]})
    rep = await prefixdns.report(REAL, 0, r)
    assert rep["delegations"] == [{"zone": "22.160.in-addr.arpa", "ns": ["ns.parent.example"], "ds": False, "ns_problems": []}]


async def test_ptr_delegation_flags_bad_name_servers():
    r = FakeResolver({"108.22.160.in-addr.arpa/NS": ["win-8h6jmqbvgp2", "ghost.example.com", "ns1.example.com", "slow.example.com", "ns6.example.com."],
                      "ns1.example.com/A": ["192.0.2.1"], "ghost.example.com/TXT": ["x"], "slow.example.com/A": "TIMEOUT", "slow.example.com/AAAA": "TIMEOUT",
                      "ns6.example.com/AAAA": ["2001:db8::6"]})
    d = (await prefixdns.report(REAL, 0, r))["delegations"][0]
    assert d["ns_problems"] == [{"ns": "ghost.example.com", "problem": "no_address"}, {"ns": "win-8h6jmqbvgp2", "problem": "not_fqdn"}]


async def test_ptr_ipv6_only_delegation():
    z = {"8.b.d.0.1.0.0.2.ip6.arpa/NS": ["ns6.example.com"]}
    rep = await prefixdns.report("2001:db8::/32", 0, FakeResolver(z))
    assert rep["family"] == 6 and rep["rows"] == [] and rep["note"] == "IPv6: only the delegation is shown"
    assert rep["delegations"][0]["zone"] == "8.b.d.0.1.0.0.2.ip6.arpa" and rep["blocks"] == 1


class SlowResolver(FakeResolver):
    """PTR lookups for .200 and above never finish within the budget."""

    async def query(self, name, rtype, *, dnssec=False):
        if rtype == "PTR" and int(name.split(".")[0]) >= 200:
            await asyncio.sleep(30)
        return await super().query(name, rtype, dnssec=dnssec)


async def test_ptr_budget_timeout_returns_partial():
    t = time.monotonic()
    rep = await prefixdns.report(REAL, 0, SlowResolver(ptr_zone()), budget=0.5)
    assert time.monotonic() - t < 5
    assert rep["partial"] is True and rep["stats"]["scanned"] == 200 and len(rep["rows"]) == 256
    assert rep["rows"][1]["ptr"] == "mail.example.com" and rep["rows"][250]["ptr"] is None and "time limit" in rep["note"]


class Once:
    """Bucket that lets exactly one call through (TokenBucket(1, 1) rejects its very first call)."""

    def __init__(self):
        self.n = 0

    def allow(self, key):
        self.n += 1
        return self.n <= 1


# --- endpoints --------------------------------------------------------------------------------------------
async def test_rdns_requires_pass(client, ts_on):
    r = await client.post(f"{API}/prefix-rdns", json={"prefix": REAL}, headers=VISITOR)
    assert r.status_code == 403 and r.json() == {"error": "pass_required"}


async def test_rdns_endpoint_contract(client, monkeypatch, ts_on):
    monkeypatch.setattr(prefixdns, "make_resolver", lambda: FakeResolver(ptr_zone()))
    r = await client.post(f"{API}/prefix-rdns", json={"prefix": REAL, "block": 0}, headers=with_pass())
    assert r.status_code == 200
    d = r.json()
    assert {"prefix", "family", "block", "blocks", "base", "delegations", "rows", "stats", "note"} <= set(d)
    assert d["prefix"] == REAL and len(d["rows"]) == 256 and d["stats"]["fcrdns_ok"] == 2 and d["delegations"][0]["ds"] is True
    assert set(d["rows"][0]) == {"ip", "ptr", "fcrdns", "auto"}
    again = await client.post(f"{API}/prefix-rdns", json={"prefix": REAL}, headers=with_pass())      # served from cache
    assert again.status_code == 200 and again.json()["stats"] == d["stats"]


async def test_rdns_ipv6_note_and_validation(client, monkeypatch, ts_on):
    monkeypatch.setattr(prefixdns, "make_resolver", lambda: FakeResolver())
    r = await client.post(f"{API}/prefix-rdns", json={"prefix": "2606:4700::/32"}, headers=with_pass())
    assert r.status_code == 200 and r.json()["family"] == 6 and r.json()["note"] == "IPv6: only the delegation is shown" and r.json()["rows"] == []
    for body in ({"prefix": "10.0.0.0/24"}, {"prefix": "nonsense"}, {"prefix": "127.0.0.1"}, {"prefix": REAL, "block": 5}, {"prefix": REAL, "block": -1}):
        assert (await client.post(f"{API}/prefix-rdns", json=body, headers=with_pass())).status_code == 422, body


async def test_rdns_per_target_cooldown(client, monkeypatch, ts_on):
    monkeypatch.setattr(prefixdns, "make_resolver", lambda: FakeResolver())
    monkeypatch.setattr(cooldown, "_bucket", Once())
    ok1 = await client.post(f"{API}/prefix-rdns", json={"prefix": "160.22.108.0/23", "block": 0}, headers=with_pass())
    ok2 = await client.post(f"{API}/prefix-rdns", json={"prefix": "160.22.108.0/23", "block": 1}, headers=with_pass())
    assert ok1.status_code == 200 and ok2.status_code == 429 and ok2.json() == {"error": "target_busy"}


async def test_whois_endpoint_is_light_and_cached(client, monkeypatch):
    calls = []

    async def fake(prefix, **kw):
        calls.append(prefix)
        return {"prefix": prefix, "records": [], "irr_records": [], "authorities": [], "abuse_email": None, "geofeed": None, "raw": "", "fetched_at": "x"}
    monkeypatch.setattr(bgp_api.prefixwhois, "report", fake)
    r = await client.get(f"{API}/prefix-whois/{REAL}", headers=VISITOR)          # no pass needed
    assert r.status_code == 200 and r.json()["prefix"] == REAL
    assert (await client.get(f"{API}/prefix-whois/160.22.108.7/24", headers=VISITOR)).json()["prefix"] == "160.22.108.0/24"
    assert len(calls) == 1                                                       # second one cached (same canonical prefix)
    for bad in ("10.0.0.0/8", "garbage", "999.1.1.0/24"):
        assert (await client.get(f"{API}/prefix-whois/{bad}", headers=VISITOR)).status_code == 422


async def test_whois_endpoint_upstream_failure_is_502_not_500(client, monkeypatch):
    async def boom(prefix, **kw):
        raise ripestat.RipeStatError("RIPEstat whois: down")
    monkeypatch.setattr(bgp_api.prefixwhois, "report", boom)
    r = await client.get(f"{API}/prefix-whois/{REAL}", headers=VISITOR)
    assert r.status_code == 502 and "RIPEstat" in r.json()["detail"]


async def test_whois_endpoint_rate_limited(client, monkeypatch):
    monkeypatch.setattr(bgp_api, "_light_bucket", Once())

    async def fake(prefix, **kw):
        return {"prefix": prefix}
    monkeypatch.setattr(bgp_api.prefixwhois, "report", fake)
    assert (await client.get(f"{API}/prefix-whois/{REAL}", headers=VISITOR)).status_code == 200
    assert (await client.get(f"{API}/prefix-whois/1.1.1.0/24", headers=VISITOR)).status_code == 429


# --- recorded sample responses ----------------------------------------------------------------------------
def test_sample_fixtures_follow_the_contract():
    rep = json.loads((FIX / "report.json").read_text())
    assert {"overview", "connectivity", "validation"} <= set(rep) and rep["prefix"] == REAL
    assert {"rir", "country", "netname", "holder", "inetnum", "reg_status", "reg_status_meaning", "registered", "age_days", "size",
            "abuse_email"} == set(rep["overview"])
    c = rep["connectivity"]
    assert {"graph", "upstreams", "paths_total", "collector_peers", "path_length", "prepending"} == set(c)
    assert {"id", "asn", "name", "role", "tier1", "depth", "paths", "share"} == set(c["graph"]["nodes"][0])
    assert {"from", "to", "count"} == set(c["graph"]["edges"][0]) and {"min", "median", "max", "hist"} == set(c["path_length"])
    v = rep["validation"]
    assert {"rpki", "irr", "summary"} == set(v) and {"available", "sources", "objects", "rpki_routes", "messages", "category"} == set(v["irr"])
    assert {"source", "prefix", "asn", "rpki_status", "exact", "matches_bgp", "rpsl"} == set(v["irr"]["objects"][0])
    assert {"asn", "state", "reason", "roas", "maxlength_loose"} == set(v["rpki"][0])
    w = json.loads((FIX / "whois.json").read_text())
    assert {"prefix", "records", "irr_records", "authorities", "abuse_email", "geofeed", "raw", "fetched_at"} == set(w)
    d = json.loads((FIX / "rdns.json").read_text())
    assert {"prefix", "family", "block", "blocks", "base", "delegations", "rows", "stats", "note"} <= set(d) and len(d["rows"]) == 256


def test_irr_stale_object_alongside_match():
    from app.core import bgpview
    irr = {"available": True, "sources": ["APNIC"], "objects": [
        {"source": "APNIC", "prefix": "160.22.108.0/24", "asn": 152523, "exact": True, "matches_bgp": True},
        {"source": "APNIC", "prefix": "160.22.108.0/24", "asn": 151734, "exact": True, "matches_bgp": False}]}
    f = bgpview.irr_findings("160.22.108.0/24", [{"asn": 152523}], irr, "match")
    ids = [x["id"] for x in f]
    assert ids == ["irr-match", "irr-stale"]
    assert "AS151734 in APNIC" in f[1]["title"] and f[1]["status"] == "warn"
