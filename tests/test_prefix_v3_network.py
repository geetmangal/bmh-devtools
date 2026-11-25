"""Live smoke test of the v3 prefix sources for 160.22.108.0/24 (RIPEstat, IRR Explorer, PeeringDB, DNS).
Deselected by default; run with `make test-network` or `pytest -m network tests/test_prefix_v3_network.py`."""
import pytest

from app.core import bgpview, prefixdns, prefixwhois

pytestmark = pytest.mark.network
P = "160.22.108.0/24"


async def test_live_prefix_v3_160_22_108_0_24():
    r = await bgpview.prefix_report(P)
    assert 152523 in [o["asn"] for o in r["origins"]]
    assert r["overview"]["rir"] == "APNIC" and r["overview"]["country"] == "IN" and r["overview"]["abuse_email"]
    assert r["overview"]["size"]["addresses"] == 256
    c = r["connectivity"]
    assert c["upstreams"] and c["paths_total"] > 0 and any(n["role"] == "origin" for n in c["graph"]["nodes"])
    v = r["validation"]
    assert v["irr"]["available"] is True and v["irr"]["objects"]
    assert v["summary"]["irr"] in ("match", "mismatch")        # route objects exist; which one depends on the registry's state today
    assert v["summary"]["rpki"] in ("valid", "invalid", "unknown")
    assert any(f["id"] in ("irr-match", "irr-mismatch") for f in r["findings"])
    print("origin", [o["asn"] for o in r["origins"]], "irr", v["summary"]["irr"], "upstreams", [u["asn"] for u in c["upstreams"]])


async def test_live_whois_and_rdns_160_22_108_0_24():
    w = await prefixwhois.report(P)
    assert w["records"] and w["authorities"] and w["abuse_email"]
    assert any(kv["key"] == "status" and kv["meaning"] for rec in w["records"] for kv in rec)
    d = await prefixdns.report(P, 0, budget=30.0)
    assert len(d["rows"]) == 256 and d["base"] == P and d["delegations"]
