"""Shared helpers + hand-written, documented-shape fixtures for the bgp tests (no network).

Not a test module itself: it holds the ``StubFetch`` router, response builders for RIPEstat,
PeeringDB and Globalping, and the autouse fixture that clears the module caches.
"""
from __future__ import annotations

import inspect
from typing import Any

import pytest

from app.core import hopenrich, peeringdb, ripestat
from app.core.httpjson import FetchError


@pytest.fixture(autouse=True)
def clean_bgp_state(monkeypatch):
    ripestat.clear_caches()
    peeringdb.clear_cache()
    hopenrich.clear_cache()
    for k in ("GLOBALPING_TOKEN", "PEERINGDB_API_KEY", "RIPESTAT_SOURCEAPP"):
        monkeypatch.delenv(k, raising=False)
    yield


def ok(data: dict) -> dict:
    """RIPEstat envelope."""
    return {"messages": [], "see_also": [], "version": "1.0", "status": "ok", "status_code": 200, "data": data}


class StubFetch:
    """Stand-in for fetch_json: routes by URL suffix, records every call."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = dict(routes)
        self.calls: list[tuple[str, dict, dict | None]] = []

    def count(self, suffix: str) -> int:
        return sum(1 for u, _p, _h in self.calls if u.endswith(suffix))

    def params(self, suffix: str) -> list[dict]:
        return [p for u, p, _h in self.calls if u.endswith(suffix)]

    async def __call__(self, url, params=None, timeout=8.0, headers=None):
        self.calls.append((url, dict(params or {}), headers))
        for key, val in self.routes.items():
            if url.endswith(key):
                v = val(params or {}) if callable(val) else val
                if inspect.isawaitable(v):
                    v = await v
                if isinstance(v, Exception):
                    raise v
                return v
        raise FetchError("not found", 404)


# --- RIPEstat fixtures (shapes follow the live API) --------------------------------------
PFX = "1.1.1.0/24"


def probe(name, ixp, city, cc, lat, lon):
    return {"city": city, "country": cc, "longitude": lon, "latitude": lat, "name": name, "ixp": ixp,
            "ipv4_peer_count": 10, "ipv6_peer_count": 8}


def vis_entry(name, total, not_seeing=0, v6_total=0, **kw):
    p = probe(name.upper(), kw.get("ixp", "X-IX"), kw.get("city", "Somewhere"), kw.get("cc", "XX"), kw.get("lat", 1.0), kw.get("lon", 2.0))
    return {"probe": p, "ipv4_full_table_peers_not_seeing": [{"asn": 64500 + i, "ip": f"192.0.2.{i}"} for i in range(not_seeing)],
            "ipv6_full_table_peers_not_seeing": [], "ipv4_full_table_peer_count": total, "ipv6_full_table_peer_count": v6_total}


def lg_peer(path: str, peer="5.57.80.113"):
    p = path.replace("{", "").replace("}", "").split()
    return {"asn_origin": p[-1], "as_path": path, "community": "", "largeCommunity": "", "extendedCommunity": "",
            "last_updated": "2026-11-22T12:40:59", "prefix": PFX, "peer": peer, "origin": "IGP", "next_hop": "5.57.81.75",
            "latest_time": "2026-11-24T20:11:51"}


def ripe_routes(*, prefix=PFX, origins=(13335,), more=(), less=(), rpki=None, announced=True, vis=None, lg=None, history=None):
    rpki = rpki or {}

    def rpki_route(p):
        st = rpki.get((int(str(p["resource"]).lstrip("AS")), p["prefix"]), "valid")
        roa_origin = {"valid": int(str(p["resource"]).lstrip("AS")), "invalid_asn": 64999, "invalid_length": int(str(p["resource"]).lstrip("AS")), "unknown": None}[st]
        roas = [] if roa_origin is None else [{"origin": str(roa_origin), "prefix": p["prefix"], "validity": st, "max_length": 24}]
        top = "valid" if st == "valid" else "unknown" if st == "unknown" else "invalid"
        return ok({"resource": p["resource"], "prefix": p["prefix"], "validating_roas": roas, "status": top, "validator": "routinator"})

    vis = vis if vis is not None else [vis_entry("RRC00", 40, 0, ixp="RIPE-NCC Multihop", city="Amsterdam", cc="NL", lat=52.3667, lon=4.8833),
                                      vis_entry("RRC01", 70, 7, ixp="LINX / LONAP", city="London", cc="GB", lat=51.4969, lon=-0.0192),
                                      vis_entry("RRC12", 50, 50, ixp="DE-CIX", city="Frankfurt", cc="DE", lat=50.1, lon=8.7),
                                      vis_entry("RRC02", 0)]
    lg = lg if lg is not None else [
        {"rrc": "RRC01", "location": "London, GB", "scope": "LINX", "peers": [lg_peer("15692 13335"), lg_peer("8218 13335", "5.57.80.2"), lg_peer("15692 15692 13335", "5.57.80.3")]},
        {"rrc": "RRC12", "location": "Frankfurt, DE", "scope": "DE-CIX", "peers": [lg_peer("15692 13335")]}]
    history = history if history is not None else [
        {"origin": "13335", "prefixes": [{"prefix": prefix, "timelines": [{"starttime": "2026-10-27T00:00:00", "endtime": "2026-11-24T00:00:00", "full_peers_seeing": 320.0}]}]}]
    return {
        "routing-status/data.json": ok({"first_seen": {"prefix": prefix, "origin": "19855", "time": "2001-11-14T00:00:00"},
                                        "last_seen": {"prefix": prefix, "origin": str(origins[0]) if origins else "0", "time": "2026-11-24T16:00:00"},
                                        "visibility": {"v4": {"ris_peers_seeing": 278, "total_ris_peers": 279}, "v6": {"ris_peers_seeing": 0, "total_ris_peers": 0}},
                                        "origins": [{"origin": o, "route_objects": ["APNIC"]} for o in origins],
                                        "less_specifics": list(less), "more_specifics": list(more), "resource": prefix}),
        "visibility/data.json": ok({"visibilities": vis, "resource": prefix, "related_prefixes": []}),
        "prefix-overview/data.json": ok({"announced": announced, "asns": [{"asn": o, "holder": f"HOLDER{o} - Net {o}"} for o in origins] if announced else [],
                                         "related_prefixes": [], "resource": prefix, "type": "prefix",
                                         "block": {"resource": "1.0.0.0/8", "desc": "APNIC (Status: ALLOCATED)"}}),
        "looking-glass/data.json": ok({"rrcs": lg}),
        "routing-history/data.json": ok({"by_origin": history}),
        "rpki-validation/data.json": rpki_route,
        "network-info/data.json": ok({"asns": [str(o) for o in origins[:1]], "prefix": prefix}),
    }


def neighbour(asn, type_, power):
    return {"asn": asn, "type": type_, "power": power, "v4_peers": power // 2, "v6_peers": power // 3}


def asn_routes(*, prefixes=None, neighbours=None, rpki=None, holder="CLOUDFLARENET - Cloudflare, Inc."):
    prefixes = prefixes if prefixes is not None else ["1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/13", "172.64.0.0/13", "2606:4700::/32"]
    neighbours = neighbours if neighbours is not None else [
        neighbour(3356, "left", 900), neighbour(174, "left", 700), neighbour(1299, "left", 50),
        neighbour(64496, "right", 10), neighbour(64497, "right", 5), neighbour(6939, "uncertain", 100)]
    rpki = rpki if rpki is not None else {"104.16.0.0/13": "unknown", "172.64.0.0/13": "invalid_asn"}

    def rpki_route(p):
        st = rpki.get(p["prefix"], "valid")
        roas = [] if st == "unknown" else [{"origin": "64999" if st == "invalid_asn" else "13335", "prefix": p["prefix"], "validity": st, "max_length": 24}]
        return ok({"resource": "13335", "prefix": p["prefix"], "validating_roas": roas,
                   "status": "valid" if st == "valid" else "unknown" if st == "unknown" else "invalid", "validator": "routinator"})

    def overview(p):
        a = int(str(p["resource"]).lstrip("AS"))
        return ok({"type": "as", "resource": str(a), "holder": holder if a == 13335 else f"HOLDER{a} - Network {a}",
                   "announced": True, "block": {"desc": "Assigned by ARIN"}})

    return {
        "as-overview/data.json": overview,
        "announced-prefixes/data.json": ok({"prefixes": [{"prefix": p, "timelines": [{"starttime": "2026-11-10T08:00:00", "endtime": "2026-11-24T08:00:00"}]} for p in prefixes]}),
        "asn-neighbours/data.json": ok({"resource": "13335", "neighbour_counts": {"left": sum(1 for n in neighbours if n["type"] == "left"), "right": sum(1 for n in neighbours if n["type"] == "right"),
                                                                                  "unique": len(neighbours), "uncertain": sum(1 for n in neighbours if n["type"] == "uncertain")},
                                        "neighbours": neighbours}),
        "rpki-validation/data.json": rpki_route,
        **pdb_routes(),
    }


# --- PeeringDB fixtures --------------------------------------------------------------------
def pdb_net(**kw):
    d = {"id": 4224, "name": "Cloudflare", "aka": "", "website": "https://www.cloudflare.com", "asn": 13335,
         "irr_as_set": "ARIN::AS13335:AS-CLOUDFLARE", "info_type": "Content", "info_prefixes4": 80000, "info_prefixes6": 30000,
         "info_traffic": "", "info_ratio": "Mostly Outbound", "info_scope": "Global", "ix_count": 357, "fac_count": 223,
         "policy_url": "https://www.cloudflare.com/peering-policy/", "policy_general": "Open", "status": "ok"}
    d.update(kw)
    return d


def pdb_routes(*, net=None, netixlan=None, ix=None, netfac=None):
    net = [pdb_net()] if net is None else net
    netixlan = netixlan if netixlan is not None else [
        {"id": 1, "net_id": 4224, "ix_id": 31, "name": "AMS-IX", "speed": 100000, "asn": 13335, "ipaddr4": "80.249.209.1", "ipaddr6": "2001:7f8:1::a501:3335:1", "is_rs_peer": True, "operational": True, "status": "ok"},
        {"id": 2, "net_id": 4224, "ix_id": 177, "name": "NIXI Mumbai", "speed": 10000, "asn": 13335, "ipaddr4": "218.100.48.5", "ipaddr6": None, "is_rs_peer": False, "operational": True, "status": "ok"}]
    ix = ix if ix is not None else [{"id": 31, "name": "AMS-IX", "city": "Amsterdam", "country": "NL"}, {"id": 177, "name": "NIXI Mumbai", "city": "Mumbai", "country": "IN"}]
    netfac = netfac if netfac is not None else [
        {"id": 22, "name": "Equinix AM3", "city": "Amsterdam", "country": "NL", "fac_id": 1, "local_asn": 13335, "status": "ok"},
        {"id": 23, "name": "Nxtra Mumbai", "city": "Mumbai", "country": "IN", "fac_id": 7, "local_asn": 13335, "status": "ok"}]
    return {"/api/net": {"data": net, "meta": {}}, "/api/netixlan": {"data": netixlan, "meta": {}},
            "/api/ix": {"data": ix, "meta": {}}, "/api/netfac": {"data": netfac, "meta": {}}}


