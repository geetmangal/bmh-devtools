"""Hop enrichment: private hops skipped, /24 dedupe, bounded concurrency, segments, summary (offline)."""
import asyncio

from app.core import hopenrich
from tests.test_bgp_fixtures import StubFetch, clean_bgp_state, ok  # noqa: F401


def hop(n, ip, rtt=None, **kw):
    return {"hop": n, "ip": ip, "rtt_ms": rtt, **kw}


class Lookup:
    def __init__(self, table=None, delay=0.0):
        self.table, self.delay, self.ips, self.active, self.peak = table or {}, delay, [], 0, 0

    async def __call__(self, ip):
        self.ips.append(ip)
        self.active += 1
        self.peak = max(self.peak, self.active)
        if self.delay:
            await asyncio.sleep(self.delay)
        self.active -= 1
        if ip in self.table:
            return self.table[ip]
        return {"asn": 64500, "as_name": "Example", "prefix": ip.rsplit(".", 1)[0] + ".0/24", "country": "IN", "city": "Mumbai", "lat": 19.0, "lon": 72.8}


AIRTEL = {"asn": 9498, "as_name": "Bharti Airtel", "prefix": "182.79.0.0/16", "country": "IN", "city": "Mumbai", "lat": 19.07, "lon": 72.88}
CF = {"asn": 13335, "as_name": "Cloudflare", "prefix": "1.1.1.0/24", "country": None, "city": None, "lat": None, "lon": None}


async def test_private_and_silent_hops_are_not_queried():
    look = Lookup()
    hops = [hop(1, "192.168.1.1", 1), hop(2, "private"), hop(3, None), hop(4, "10.1.2.3", 3), hop(5, "100.64.0.9", 4),
            hop(6, "169.254.1.1"), hop(7, "127.0.0.1"), hop(8, "fd00::1"), hop(9, "8.8.8.8", 20)]
    out = await hopenrich.enrich_hops(hops, lookup=look)
    assert look.ips == ["8.8.8.8"]
    assert [h["private"] for h in out] == [True, True, False, True, True, True, True, True, False]
    assert out[2]["timeout"] is True and out[2]["asn"] is None
    assert out[0]["asn"] is None and out[0]["country"] is None
    assert out[8]["asn"] == 64500 and out[8]["city"] == "Mumbai"
    assert hops[0].keys() == {"hop", "ip", "rtt_ms"}               # input not mutated


async def test_lookups_deduplicated_per_slash24():
    look = Lookup()
    hops = [hop(1, "1.1.1.1"), hop(2, "1.1.1.2"), hop(3, "1.1.1.200"), hop(4, "8.8.8.8"), hop(5, "8.8.4.4"), hop(6, "8.8.8.9"),
            hop(7, "2606:4700::1"), hop(8, "2606:4700::2")]
    out = await hopenrich.enrich_hops(hops, lookup=look)
    assert sorted(look.ips) == ["1.1.1.1", "2606:4700::1", "8.8.4.4", "8.8.8.8"]
    assert out[1]["prefix"] == out[0]["prefix"] and out[2]["asn"] == 64500 and out[5]["asn"] == out[3]["asn"]
    assert hopenrich.group_key("1.1.1.77") == "1.1.1.0/24" and hopenrich.group_key("2606:4700:1:2::9") == "2606:4700:1::/48"


async def test_second_call_hits_cache_and_concurrency_is_bounded():
    look = Lookup(delay=0.02)
    hops = [hop(i, f"9.{i}.0.1") for i in range(1, 15)]
    await hopenrich.enrich_hops(hops, lookup=look)
    assert len(look.ips) == 14 and look.peak <= 6 and look.peak > 1
    await hopenrich.enrich_hops(hops, lookup=look)
    assert len(look.ips) == 14                                      # cached


async def test_failed_lookup_marks_hop_without_breaking_the_trace():
    async def boom(ip):
        raise RuntimeError("x")

    out = await hopenrich.enrich_hops([hop(1, "8.8.8.8", 5)], lookup=boom)
    assert out[0]["lookup_failed"] is True and out[0]["asn"] is None and out[0]["private"] is False
    # failures are not cached
    out = await hopenrich.enrich_hops([hop(1, "8.8.8.8", 5)], lookup=Lookup())
    assert out[0]["asn"] == 64500


async def test_ripe_lookup_combines_network_info_overview_and_geo():
    f = StubFetch({
        "network-info/data.json": ok({"asns": ["13335"], "prefix": "1.1.1.0/24"}),
        "as-overview/data.json": ok({"holder": "CLOUDFLARENET - Cloudflare, Inc.", "announced": True}),
        "maxmind-geo-lite/data.json": ok({"located_resources": [{"resource": "1.1.1.1/32", "locations": [
            {"country": "AU", "city": "Sydney", "resources": ["1.1.1.0/24"], "latitude": -33.86, "longitude": 151.2, "covered_percentage": 100}]}]})})
    out = await hopenrich.enrich_hops([hop(1, "1.1.1.1", 9), hop(2, "1.1.1.9", 10)], fetch=f)
    assert out[1]["asn"] == 13335 and out[1]["as_name"] == "Cloudflare, Inc." and out[1]["prefix"] == "1.1.1.0/24"
    assert (out[1]["country"], out[1]["city"], out[1]["lat"]) == ("AU", "Sydney", -33.86)
    assert f.count("network-info/data.json") == 1                   # one lookup for the shared /24


async def test_ripe_down_degrades_to_unknown_asn():
    f = StubFetch({})                                               # every call 404s -> RipeStatError
    out = await hopenrich.enrich_hops([hop(1, "8.8.8.8", 5)], fetch=f)
    assert out[0]["lookup_failed"] is True


def path_hops():
    base = [hop(1, "192.168.1.1", 1.0, private=True), hop(2, "182.79.1.1", 4.0, asn=9498, as_name="Bharti Airtel", private=False, country="IN"),
            hop(3, "182.79.1.2", 5.0, asn=9498, as_name="Bharti Airtel", private=False), hop(4, None, None, asn=None, private=False, timeout=True),
            hop(5, "182.79.1.3", 7.0, asn=9498, as_name="Bharti Airtel", private=False),
            hop(6, "1.1.1.1", 17.0, asn=13335, as_name="Cloudflare", private=False), hop(7, "1.1.1.2", 18.0, asn=13335, as_name="Cloudflare", private=False)]
    return base


def test_asn_segments_group_consecutive_hops_and_skip_silent_ones():
    segs = hopenrich.asn_segments(path_hops())
    assert [(s["asn"], s["private"], s["hops"]) for s in segs] == [(None, True, [1]), (9498, False, [2, 3, 5]), (13335, False, [6, 7])]
    assert segs[1]["start_hop"] == 2 and segs[1]["end_hop"] == 5 and segs[1]["hop_count"] == 3
    assert segs[1]["label"] == "AS9498 Bharti Airtel" and segs[0]["label"] == "Private network" and segs[2]["rtt_ms"] == 18.0


def test_a_return_to_an_earlier_asn_starts_a_new_segment():
    hops = [hop(1, "1.0.0.1", 1, asn=1, as_name="A", private=False), hop(2, "2.0.0.1", 2, asn=2, as_name="B", private=False),
            hop(3, "1.0.0.2", 3, asn=1, as_name="A", private=False)]
    assert [s["asn"] for s in hopenrich.asn_segments(hops)] == [1, 2, 1]


def test_summary_text_leaves_via_enters_at_hop_latency_no_loss():
    s = hopenrich.summarise_path(path_hops(), loss_pct=0)
    assert s == "Leaves via AS9498 Bharti Airtel, enters AS13335 Cloudflare at hop 6, 18 ms end-to-end, no loss."


def test_summary_variants():
    hops = path_hops()
    mid = hops[:5] + [hop(6, "4.0.0.1", 10, asn=3356, as_name="Lumen", private=False)] + [h | {"hop": h["hop"] + 1} for h in hops[5:]]
    assert hopenrich.summarise_path(mid, loss_pct=0).startswith("Leaves via AS9498 Bharti Airtel, passes through AS3356 Lumen, enters AS13335 Cloudflare at hop 7")
    assert hopenrich.summarise_path(hops, loss_pct=12.5).endswith("18 ms end-to-end, 12.5% loss.")
    assert hopenrich.summarise_path(hops).endswith("18 ms end-to-end.")        # unknown loss: no claim
    single = [hop(1, "1.0.0.1", 2.5, asn=1, as_name="A", private=False), hop(2, "1.0.0.2", 3.25, asn=1, as_name="A", private=False)]
    assert hopenrich.summarise_path(single, 0) == "Stays within AS1 A (hop 1-2), 3.2 ms end-to-end, no loss."
    assert hopenrich.summarise_path([hop(1, None, None, private=False, asn=None), hop(2, "192.168.0.1", 1, private=True, asn=None)]).startswith("No public hop answered")


async def test_analyse_path_end_to_end_with_stub_lookup():
    look = Lookup({"182.79.1.1": AIRTEL, "182.79.1.2": AIRTEL, "1.1.1.1": CF})
    hops = [hop(1, "192.168.1.1", 1), hop(2, "182.79.1.1", 4), hop(3, "182.79.1.2", 6), hop(4, "1.1.1.1", 18)]
    r = await hopenrich.analyse_path(hops, loss_pct=0, lookup=look)
    assert r["summary"] == "Leaves via AS9498 Bharti Airtel, enters AS13335 Cloudflare at hop 4, 18 ms end-to-end, no loss."
    assert [s["asn"] for s in r["segments"]] == [None, 9498, 13335] and r["hops"][0]["private"] is True
    assert "192.168.1.1" not in look.ips and len(look.ips) == 2
