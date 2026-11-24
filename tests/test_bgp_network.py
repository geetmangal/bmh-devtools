"""Live smoke tests against the real RIPEstat / PeeringDB (skipped by `make test`; run `make test-network -k bgp`)."""
import pytest

from app.core import bgpview, peeringdb, ripestat

pytestmark = pytest.mark.network


async def test_live_ripestat_as13335():
    ov = await ripestat.as_overview(13335)
    assert ov["announced"] and "cloudflare" in (ov["holder"] or "").lower()
    pf = await ripestat.announced_prefixes(13335)
    assert pf["count"] > 100 and pf["v4"] > 0
    nb = await ripestat.asn_neighbours(13335)
    assert nb["upstreams"] and nb["downstreams"]


async def test_live_prefix_report_1_1_1_0_24():
    r = await bgpview.prefix_report("1.1.1.0/24")
    assert 13335 in [o["asn"] for o in r["origins"]]
    assert r["origins"][0]["rpki"]["state"] == "valid"
    assert r["visibility"]["total_collectors"] >= 15 and r["visibility"]["seen_collectors"] >= 10
    assert any(c["lat"] is not None for c in r["visibility"]["collectors"])
    assert r["as_paths"] and r["history"]["timeline"]
    assert r["status"] in ("pass", "warn", "fail")


async def test_live_peeringdb_cloudflare():
    r = await peeringdb.net_by_asn(13335)
    if r["partial"]:
        pytest.skip("PeeringDB anonymous rate limit hit: " + "; ".join(r["notes"]))
    assert r["found"] and r["name"] == "Cloudflare" and r["policy"]
