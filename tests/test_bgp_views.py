"""asn_report / prefix_report aggregators: graph, RPKI math, MOAS, collector join, findings, budget (offline)."""
import asyncio
import json
import time

import pytest

from app.core import bgpview, ripestat
from app.core.httpjson import FetchError
from tests.test_bgp_fixtures import (PFX, StubFetch, asn_routes, clean_bgp_state, lg_peer, neighbour, pdb_routes,  # noqa: F401
                                     ripe_routes, vis_entry)


def fid(report, id_):
    return next((f for f in report["findings"] if f["id"] == id_), None)


# --- helpers ---------------------------------------------------------------------------------------
def test_rpki_coverage_math():
    c = bgpview.rpki_coverage(["valid", "valid", "valid", "invalid", "unknown", None, None])
    assert c == {"checked": 5, "valid": 3, "invalid": 1, "unknown": 1, "covered_pct": 80.0, "valid_pct": 60.0, "no_roa_pct": 20.0}
    z = bgpview.rpki_coverage([None, None])
    assert z["checked"] == 0 and z["covered_pct"] is None
    assert bgpview.rpki_coverage(["unknown"] * 8 + ["valid"])["no_roa_pct"] == 88.9


def test_collectors_json_is_sane():
    c = bgpview.load_collectors()
    assert "rrc00" in c and "rrc12" in c and "rrc26" in c and "rrc02" not in c
    assert len(c) >= 20
    for cid, e in c.items():
        assert cid.startswith("rrc") and -90 <= e["lat"] <= 90 and -180 <= e["lon"] <= 180 and e["city"] and len(e["country"]) == 2
    assert c["rrc21"]["approx"] is True and c["rrc12"]["approx"] is False
    json.loads(bgpview._COLLECTORS.read_text())


def test_collapse_path_and_top_paths_dedupe():
    assert bgpview.collapse_path([1, 1, 1, 2, 3, 3]) == ([1, 2, 3], True)
    assert bgpview.collapse_path([1, 2]) == ([1, 2], False)
    lg = {"rrcs": [{"rrc": f"rrc{i:02d}", "peers": [{"as_path": [100 + (i % 3), 13335]}, {"as_path": [100, 100, 13335]}]} for i in range(12)]}
    paths = bgpview.top_paths(lg)
    assert len(paths) == 3 and paths[0]["path"] == [100, 13335]                 # prepended duplicate folded into the same path
    assert paths[0]["count"] == 12 + 4 and paths[0]["prepended"] is True and len(paths[0]["collectors"]) == 12
    many = {"rrcs": [{"rrc": "rrc00", "peers": [{"as_path": [1000 + i, 13335]} for i in range(30)]}]}
    assert len(bgpview.top_paths(many)) == 10


def test_resource_validation():
    assert bgpview.parse_resource("1.1.1.1") == ("1.1.1.1", True)
    assert bgpview.parse_resource("1.1.1.5/24") == ("1.1.1.0/24", False)
    for bad in ("10.0.0.0/8", "192.168.1.1", "127.0.0.1", "::1", "fd00::/8", "foo", "", "1.1.1.1/99", "AS13335"):
        with pytest.raises(bgpview.BgpInputError):
            bgpview.parse_resource(bad)


# --- ASN report ------------------------------------------------------------------------------------
async def test_asn_report_full():
    f = StubFetch(asn_routes())
    r = await bgpview.asn_report("AS13335", fetch=f)
    assert r["asn"] == 13335 and r["name"] == "Cloudflare, Inc." and r["announced"] is True
    assert r["missing"] == [] and r["partial"] is False
    assert (r["prefixes"]["count"], r["prefixes"]["v4"], r["prefixes"]["v6"]) == (5, 4, 1)
    assert {p["prefix"]: p["rpki"] for p in r["prefixes"]["list"]}["104.16.0.0/13"] == "unknown"
    assert r["rpki"] == {"checked": 5, "valid": 3, "invalid": 1, "unknown": 1, "covered_pct": 80.0, "valid_pct": 60.0, "no_roa_pct": 20.0}
    nb = r["neighbours"]
    assert [n["asn"] for n in nb["upstreams"]] == [3356, 174, 1299] and [n["asn"] for n in nb["downstreams"]] == [64496, 64497]
    assert [n["asn"] for n in nb["peers"]] == [6939] and nb["upstreams"][0]["name"] == "Network 3356"
    assert r["peeringdb"]["name"] == "Cloudflare" and r["peeringdb"]["policy"] == "Open" and r["peeringdb"]["ix_count"] == 2
    assert [x["city"] for x in r["peeringdb"]["ix_list"]] == ["Amsterdam", "Mumbai"] and len(r["peeringdb"]["facilities"]) == 2
    assert "AS13335" in r["summary"] and "5 prefixes" in r["summary"] and r["status"] == "fail"       # the invalid prefix


async def test_asn_graph_layered_with_roles_and_edges():
    r = await bgpview.asn_report(13335, fetch=StubFetch(asn_routes()))
    g = r["graph"]
    nodes = {n["id"]: n for n in g["nodes"]}
    assert nodes["AS13335"]["role"] == "target" and nodes["AS13335"]["layer"] == 1
    assert nodes["AS3356"]["role"] == "upstream" and nodes["AS3356"]["layer"] == 0 and nodes["AS3356"]["power"] == 900
    assert nodes["AS64496"]["role"] == "downstream" and nodes["AS64496"]["layer"] == 2 and nodes["AS6939"]["role"] == "peer"
    assert nodes["AS3356"]["name"] == "Network 3356" and nodes["AS13335"]["name"] == "Cloudflare, Inc."
    edges = {(e["source"], e["target"], e["type"]) for e in g["edges"]}
    assert ("AS3356", "AS13335", "transit") in edges and ("AS13335", "AS64496", "transit") in edges and ("AS13335", "AS6939", "peer") in edges
    assert len(g["nodes"]) == 7 and len(g["edges"]) == 6
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])


async def test_neighbours_capped_at_top_25_by_power():
    ups = [neighbour(10000 + i, "left", i + 1) for i in range(40)]
    r = await bgpview.asn_report(13335, fetch=StubFetch(asn_routes(neighbours=ups)))
    got = r["neighbours"]["upstreams"]
    assert len(got) == 25 and got[0]["power"] == 40 and got[-1]["power"] == 16
    assert sum(1 for n in r["graph"]["nodes"] if n["role"] == "upstream") == 25
    assert r["neighbours"]["counts"]["left"] == 40                                   # true count still reported


async def test_prefix_list_capped_500_and_rpki_sampled_100():
    pfx = [f"44.{i // 250}.{i % 250}.0/24" for i in range(600)]
    f = StubFetch(asn_routes(prefixes=pfx, rpki={}))
    r = await bgpview.asn_report(13335, fetch=f)
    assert r["prefixes"]["count"] == 600 and len(r["prefixes"]["list"]) == 500 and r["prefixes"]["truncated"] is True
    assert f.count("rpki-validation/data.json") == 100 and r["rpki"]["checked"] == 100
    assert sum(1 for p in r["prefixes"]["list"] if p["rpki"]) == 100
    assert "first 100 of 600" in fid(r, "rpki")["title"] or fid(r, "rpki")["status"] == "pass"


async def test_findings_no_roa_percentage_single_upstream_no_ix():
    pfx = [f"44.0.{i}.0/24" for i in range(8)]
    rp = {pfx[0]: "unknown"}
    f = StubFetch(asn_routes(prefixes=pfx, rpki=rp, neighbours=[neighbour(3356, "left", 100)]) | pdb_routes(netixlan=[], ix=[]))
    r = await bgpview.asn_report(13335, fetch=f)
    rp_f = fid(r, "rpki")
    assert rp_f["status"] == "warn" and rp_f["title"].startswith("12.5% of your prefixes have no ROA") and "hijacks can't be filtered" in rp_f["title"]
    assert rp_f["fix"] and rp_f["meaning"] and rp_f["details"]["unknown"] == 1
    up = fid(r, "upstreams")
    assert up["status"] == "warn" and up["title"] == "Single upstream: no transit redundancy" and up["details"]["upstreams"] == [3356]
    ix = fid(r, "ix")
    assert ix["status"] == "warn" and ix["title"] == "No IX presence listed in PeeringDB"
    assert {"id", "status", "title", "meaning", "fix", "details"} <= set(ix)
    assert r["status"] == "warn" and fid(r, "ipv6")["status"] == "info"


async def test_findings_all_good_and_no_peeringdb_record():
    r = await bgpview.asn_report(13335, fetch=StubFetch(asn_routes(rpki={}) | pdb_routes(net=[])))
    assert fid(r, "rpki")["status"] == "pass" and fid(r, "upstreams")["status"] == "pass"
    assert fid(r, "peeringdb")["status"] == "warn" and fid(r, "ix") is None


async def test_irr_as_set_missing_is_flagged():
    routes = asn_routes() | pdb_routes(net=[{"id": 1, "name": "X", "asn": 13335, "irr_as_set": "", "policy_general": "Open", "info_type": "NSP"}])
    r = await bgpview.asn_report(13335, fetch=StubFetch(routes))
    assert fid(r, "irr")["title"] == "No IRR as-set in PeeringDB"


async def test_failed_parts_are_listed_in_missing_not_raised():
    routes = asn_routes()
    routes["asn-neighbours/data.json"] = FetchError("upstream request failed: ReadTimeout")
    routes["/api/netixlan"] = FetchError("upstream returned HTTP 429")
    r = await bgpview.asn_report(13335, fetch=StubFetch(routes))
    assert set(r["missing"]) == {"neighbours", "ix"} and r["partial"] is True
    assert r["neighbours"] is None and "ReadTimeout" in r["errors"]["neighbours"]
    assert r["prefixes"]["count"] == 5 and fid(r, "upstreams") is None                       # no claim without data
    assert r["graph"]["nodes"][0]["id"] == "AS13335" and r["graph"]["edges"] == []
    assert any("rate limit" in n.lower() for n in r["notes"])


async def test_pdb_rate_limit_marks_partial():
    routes = asn_routes()
    routes["/api/net"] = FetchError("upstream returned HTTP 429")
    r = await bgpview.asn_report(13335, fetch=StubFetch(routes))
    assert "peeringdb" in r["missing"] and fid(r, "peeringdb") is None and r["prefixes"]["count"] == 5


async def test_asn_report_budget_returns_partial_data_fast():
    async def slow(_p):
        await asyncio.sleep(10)

    routes = asn_routes()
    routes["asn-neighbours/data.json"] = slow
    t = time.monotonic()
    r = await bgpview.asn_report(13335, fetch=StubFetch(routes), budget=0.4)
    assert time.monotonic() - t < 3
    assert "neighbours" in r["missing"] and r["errors"]["neighbours"] == "timed out" and r["prefixes"]["count"] == 5
    assert r["partial"] is True and r["elapsed_ms"] < 3000


async def test_asn_report_rejects_garbage_asn():
    with pytest.raises(bgpview.BgpInputError):
        await bgpview.asn_report("1.1.1.1", fetch=StubFetch({}))


# --- prefix report ---------------------------------------------------------------------------------
async def test_prefix_report_clean_single_origin():
    r = await bgpview.prefix_report("1.1.1.0/24", fetch=StubFetch(ripe_routes()))
    assert r["prefix"] == PFX and r["moas"] is False and [o["asn"] for o in r["origins"]] == [13335]
    assert r["origins"][0]["rpki"]["state"] == "valid" and r["origins"][0]["holder"] == "HOLDER13335 - Net 13335"
    assert r["missing"] == [] and r["announced"] is True
    assert fid(r, "rpki-AS13335")["status"] == "pass" and fid(r, "moas") is None and fid(r, "more-specific-other-as") is None
    assert r["summary"].startswith("1.1.1.0/24 is originated by AS13335 Net 13335, RPKI valid, seen by 2 of 3 RIS collectors")
    assert r["first_seen"]["origin"] == "19855" and r["block"].startswith("APNIC")


async def test_visibility_joined_with_collector_coordinates():
    r = await bgpview.prefix_report("1.1.1.0/24", fetch=StubFetch(ripe_routes()))
    v = r["visibility"]
    by = {c["id"]: c for c in v["collectors"]}
    assert (v["seen_collectors"], v["total_collectors"]) == (2, 3)
    assert (by["rrc01"]["seen"], by["rrc01"]["total"], by["rrc01"]["is_seen"]) == (63, 70, True)
    assert (by["rrc12"]["seen"], by["rrc12"]["is_seen"]) == (0, False)
    assert (by["rrc01"]["lat"], by["rrc01"]["lon"], by["rrc01"]["city"]) == (51.4969, -0.0192, "London")   # from ris_collectors.json
    assert by["rrc12"]["lat"] == 50.1124 and by["rrc12"]["name"] == "DE-CIX"                                  # json wins over RIPE probe data
    assert by["rrc26"]["no_data"] is True and by["rrc26"]["lat"] == 25.2697                                   # known collector RIPE did not report
    assert by["rrc02"]["no_data"] is True                                                                     # reported with 0 full-table peers
    assert v["seen_peers"] == 103 and v["total_peers"] == 160
    f = fid(r, "visibility")
    assert f["title"] == "Visible on 2 of 3 collectors" and f["status"] == "warn" and f["details"]["not_seen"] == ["rrc12"]


async def test_visibility_all_collectors_pass():
    vis = [vis_entry("RRC00", 10), vis_entry("RRC01", 10)]
    r = await bgpview.prefix_report("1.1.1.0/24", fetch=StubFetch(ripe_routes(vis=vis)))
    assert fid(r, "visibility")["status"] == "pass" and fid(r, "visibility")["title"] == "Visible on 2 of 2 collectors"


async def test_moas_detected_and_rpki_invalid_flagged():
    routes = ripe_routes(origins=(13335, 64500), rpki={(64500, PFX): "invalid_asn"})
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    assert r["moas"] is True and [o["asn"] for o in r["origins"]] == [13335, 64500]
    moas = fid(r, "moas")
    assert moas["status"] == "warn" and "AS13335" in moas["title"] and "AS64500" in moas["title"]
    inv = fid(r, "rpki-AS64500")
    assert inv["status"] == "fail" and inv["title"] == "RPKI invalid: origin AS doesn't match the ROA"
    assert r["status"] == "fail" and "MOAS" in r["summary"] and "invalid/valid" in r["summary"]


async def test_rpki_unknown_and_invalid_length_titles():
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes(rpki={(13335, PFX): "unknown"})))
    assert fid(r, "rpki-AS13335")["status"] == "warn" and "No ROA" in fid(r, "rpki-AS13335")["title"]
    ripestat.clear_caches()
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes(rpki={(13335, PFX): "invalid_length"})))
    assert "longer than the ROA allows" in fid(r, "rpki-AS13335")["title"]


async def test_more_specific_by_different_as_is_a_hijack_warning():
    routes = ripe_routes(more=[{"prefix": "1.1.1.0/25", "origin": 64511}, {"prefix": "1.1.1.128/25", "origin": 13335}],
                         less=[{"prefix": "1.1.0.0/16", "origin": 64600}])
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    f = fid(r, "more-specific-other-as")
    assert f["status"] == "warn" and f["title"].startswith("More-specific /25 announced by a different AS")
    assert "hijack" in f["title"] and [e["prefix"] for e in f["details"]["examples"]] == ["1.1.1.0/25"]
    assert r["less_specifics"][0]["prefix"] == "1.1.0.0/16" and len(r["more_specifics"]) == 2


async def test_history_timeline_and_origin_change_finding():
    hist = [{"origin": "64500", "prefixes": [{"prefix": PFX, "timelines": [{"starttime": "2026-10-27T00:00:00", "endtime": "2026-11-10T23:59:59", "full_peers_seeing": 5}]}]},
            {"origin": "13335", "prefixes": [{"prefix": PFX, "timelines": [{"starttime": "2026-11-11T00:00:00", "endtime": "2026-11-24T00:00:00", "full_peers_seeing": 300}]}]}]
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes(history=hist)))
    assert [t["origin"] for t in r["history"]["timeline"]] == [64500, 13335] and r["history"]["days"] == 30
    f = fid(r, "origin-change")
    assert f["status"] == "warn" and "AS64500 > AS13335" in f["title"]


async def test_as_paths_deduped_top10_for_diagram():
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes()))
    p = r["as_paths"]
    assert p[0] == {"path": [15692, 13335], "origin": 13335, "count": 3, "prepended": True, "collectors": ["rrc01", "rrc12"]}
    assert len(p) == 2 and p[1]["path"] == [8218, 13335]
    ripestat.clear_caches()
    peers = [lg_peer(f"{1000 + i} 13335") for i in range(25)]
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(ripe_routes(lg=[{"rrc": "RRC00", "location": "x", "peers": peers}])))
    assert len(r["as_paths"]) == 10


async def test_ip_input_resolves_to_covering_prefix():
    f = StubFetch(ripe_routes())
    r = await bgpview.prefix_report("1.1.1.1", fetch=f)
    assert r["is_ip"] is True and r["queried"] == "1.1.1.1" and r["prefix"] == PFX
    assert f.count("network-info/data.json") == 1 and all(p["resource"] == PFX for p in f.params("routing-status/data.json"))


async def test_private_input_rejected_without_any_request():
    f = StubFetch(ripe_routes())
    with pytest.raises(bgpview.BgpInputError):
        await bgpview.prefix_report("192.168.0.0/16", fetch=f)
    assert f.calls == []


async def test_not_announced_prefix():
    routes = ripe_routes(origins=(), announced=False, vis=[vis_entry("RRC00", 10, 10)], lg=[], history=[])
    routes["routing-status/data.json"] = {"status": "ok", "data": {"origins": [], "visibility": {}, "less_specifics": [], "more_specifics": []}}
    r = await bgpview.prefix_report("1.1.1.0/24", fetch=StubFetch(routes))
    assert r["announced"] is False and r["origins"] == [] and fid(r, "announced")["status"] == "fail"
    assert r["summary"] == "1.1.1.0/24 is not announced in the global routing table." and r["status"] == "fail"


async def test_prefix_report_partial_when_sections_fail():
    routes = ripe_routes()
    routes["looking-glass/data.json"] = FetchError("upstream request failed: ReadTimeout")
    routes["routing-history/data.json"] = {"status": "error", "messages": [["error", "x"]], "data": {}}
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes))
    assert set(r["missing"]) == {"as_paths", "history"} and r["as_paths"] is None and r["history"] is None
    assert r["origins"][0]["asn"] == 13335 and r["visibility"]["total_collectors"] == 3


async def test_prefix_report_budget_returns_partial_not_error():
    async def slow(_p):
        await asyncio.sleep(10)

    routes = ripe_routes()
    routes["visibility/data.json"] = slow
    routes["looking-glass/data.json"] = slow
    t = time.monotonic()
    r = await bgpview.prefix_report(PFX, fetch=StubFetch(routes), budget=0.4)
    assert time.monotonic() - t < 3
    assert {"visibility", "as_paths"} <= set(r["missing"]) and r["visibility"] is None
    assert r["origins"][0]["asn"] == 13335 and r["partial"] is True
    assert r["errors"]["visibility"] == "timed out"
