"""Enrich traceroute hops with ASN / prefix / geo, build ASN segments and a plain-English summary.

Input is the ``parse_traceroute`` shape: ``[{"hop": 1, "ip": "10.0.0.1" | "private" | None, "rtt_ms": 1.2}, ...]``.
Private / reserved hops are marked ``private: True`` and are never sent to any API. Lookups are
de-duplicated per /24 (IPv4) or /48 (IPv6), bounded to 6 concurrent, and cached for an hour.
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, Awaitable, Callable

from app.core import ripestat
from app.core.cache import TTLCache
from app.core.validate import is_public_ip

Lookup = Callable[[str], Awaitable[dict]]

CONCURRENCY = 6
_cache = TTLCache(3600.0, max_entries=2048)
_EMPTY = {"asn": None, "as_name": None, "prefix": None, "country": None, "city": None, "lat": None, "lon": None}


def clear_cache() -> None:
    _cache._d.clear()


def group_key(ip: str) -> str:
    """/24 for IPv4, /48 for IPv6: hops in one such block share a lookup."""
    a = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))


async def ripe_lookup(ip: str, fetch: ripestat.Fetch | None = None) -> dict:
    """ASN + prefix (network-info), AS name (as-overview), location (maxmind-geo-lite) for one IP."""
    ni = await ripestat.network_info(ip, fetch)
    asn = ni["asns"][0] if ni["asns"] else None
    out = {**_EMPTY, "asn": asn, "prefix": ni["prefix"]}

    async def name() -> None:
        if asn is not None:
            try:
                out["as_name"] = (await ripestat.as_overview(asn, fetch))["name"]
            except ripestat.RipeStatError:
                pass

    async def geo() -> None:
        try:
            g = await ripestat.geoloc(ip, fetch)
            out.update(country=g["country"], city=g["city"], lat=g["lat"], lon=g["lon"])
        except ripestat.RipeStatError:
            pass

    await asyncio.gather(name(), geo())
    return out


def _classify(ip: Any) -> str:
    """'private' | 'none' | 'public'."""
    if ip is None or ip == "":
        return "none"
    if ip == "private":
        return "private"
    try:
        ipaddress.ip_address(str(ip))
    except ValueError:
        return "none"
    return "public" if is_public_ip(str(ip)) else "private"


async def enrich_hops(hops: list[dict], *, fetch: ripestat.Fetch | None = None, lookup: Lookup | None = None,
                      concurrency: int = CONCURRENCY) -> list[dict]:
    """Return a copy of ``hops`` with private, asn, as_name, prefix, country, city, lat, lon."""
    look = lookup or (lambda ip: ripe_lookup(ip, fetch))
    kinds = [_classify(h.get("ip")) for h in hops]
    reps: dict[str, str] = {}                       # group key -> first IP seen in it
    for h, k in zip(hops, kinds):
        if k == "public":
            reps.setdefault(group_key(h["ip"]), h["ip"])
    sem = asyncio.Semaphore(max(1, concurrency))
    results: dict[str, dict | None] = {}

    async def one(key: str, ip: str) -> None:
        if (hit := _cache.get(key)) is not None:
            results[key] = hit
            return
        async with sem:
            try:
                res = {**_EMPTY, **(await look(ip))}
            except Exception:                       # a failed lookup must not break the trace view
                results[key] = None
                return
        _cache.set(key, res)
        results[key] = res

    await asyncio.gather(*(one(k, ip) for k, ip in reps.items()))
    out = []
    for h, k in zip(hops, kinds):
        e = dict(h)
        e.update(_EMPTY)
        e["private"] = k == "private"
        if k == "none":
            e["timeout"] = True
        if k == "public":
            res = results.get(group_key(h["ip"]))
            if res is None:
                e["lookup_failed"] = True
            else:
                e.update({f: res.get(f) for f in _EMPTY})
        out.append(e)
    return out


def asn_segments(hops: list[dict]) -> list[dict]:
    """Consecutive hops in the same ASN (private hops form their own segment; silent / unmapped
    hops are skipped so they do not split a segment)."""
    segs: list[dict] = []
    for h in hops:
        if h.get("private"):
            key: Any = "private"
        elif h.get("asn") is not None:
            key = h["asn"]
        else:
            continue
        if segs and segs[-1]["_key"] == key:
            s = segs[-1]
        else:
            s = {"_key": key, "asn": None if key == "private" else key, "as_name": None if key == "private" else h.get("as_name"),
                 "private": key == "private", "start_hop": h.get("hop"), "end_hop": h.get("hop"), "hops": [],
                 "country": h.get("country"), "rtt_ms": None}
            segs.append(s)
        s["end_hop"] = h.get("hop")
        s["hops"].append(h.get("hop"))
        if h.get("rtt_ms") is not None:
            s["rtt_ms"] = h["rtt_ms"]
        if not s["as_name"] and not s["private"]:
            s["as_name"] = h.get("as_name")
    for s in segs:
        s["hop_count"] = len(s["hops"])
        s["label"] = "Private network" if s["private"] else (f"AS{s['asn']} {s['as_name']}" if s["as_name"] else f"AS{s['asn']}")
        del s["_key"]
    return segs


def _ms(v: float) -> str:
    return f"{v:.0f} ms" if v >= 10 else f"{v:.1f} ms"


def summarise_path(hops: list[dict], loss_pct: float | None = None, segments: list[dict] | None = None) -> str:
    segs = segments if segments is not None else asn_segments(hops)
    pub = [s for s in segs if not s["private"]]
    parts: list[str] = []
    if not pub:
        parts.append("No public hop answered, so the path cannot be mapped to networks")
    elif len(pub) == 1:
        s = pub[0]
        parts.append(f"Stays within {s['label']} (hop {s['start_hop']}" + (f"-{s['end_hop']}" if s["end_hop"] != s["start_hop"] else "") + ")")
    else:
        parts.append(f"Leaves via {pub[0]['label']}")
        if len(pub) > 2:
            parts.append("passes through " + ", ".join(s["label"] for s in pub[1:-1]))
        parts.append(f"enters {pub[-1]['label']} at hop {pub[-1]['start_hop']}")
    rtts = [h["rtt_ms"] for h in hops if h.get("rtt_ms") is not None]
    if rtts:
        parts.append(f"{_ms(rtts[-1])} end-to-end")
    if loss_pct is None and hops and hops[-1].get("loss") is not None:
        loss_pct = hops[-1]["loss"]
    if loss_pct is not None:
        parts.append("no loss" if loss_pct == 0 else f"{loss_pct:g}% loss")
    return ", ".join(parts) + "."


async def analyse_path(hops: list[dict], *, loss_pct: float | None = None, fetch: ripestat.Fetch | None = None,
                       lookup: Lookup | None = None) -> dict:
    """enrich + segments + summary in one call."""
    enriched = await enrich_hops(hops, fetch=fetch, lookup=lookup)
    segs = asn_segments(enriched)
    return {"hops": enriched, "segments": segs, "summary": summarise_path(enriched, loss_pct, segs)}
