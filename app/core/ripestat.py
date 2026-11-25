"""RIPEstat data-call wrappers: cached, trimmed dicts, injectable fetch function.

Every public coroutine takes an optional ``fetch`` (same signature as
``app.core.httpjson.fetch_json``) so tests can stub the network. Errors (HTTP failure,
``status != ok``, unusable payload) raise ``RipeStatError``; callers that aggregate catch it
and report the part as missing.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
from typing import Any, Awaitable, Callable

from app.core.cache import TTLCache
from app.core.config import RIPESTAT_TIMEOUT, RIPESTAT_URL
from app.core.httpjson import FetchError, fetch_json

Fetch = Callable[..., Awaitable[Any]]


class RipeStatError(Exception):
    """RIPEstat unreachable, returned status != ok, or sent an unusable payload."""


def sourceapp() -> str:
    return os.environ.get("RIPESTAT_SOURCEAPP") or "bookmyhost-tools"


# --- cache: one TTLCache per TTL value --------------------------------------------------
TTL_SHORT = 300.0      # 5 min: live-ish routing state
TTL_MID = 900.0        # 15 min
TTL_LONG = 3600.0      # 60 min: registry-ish data
_caches: dict[float, TTLCache] = {}


def _cache(ttl: float) -> TTLCache:
    if ttl not in _caches:
        _caches[ttl] = TTLCache(ttl, max_entries=1024)
    return _caches[ttl]


def clear_caches() -> None:
    for c in _caches.values():
        c._d.clear()


async def call(endpoint: str, params: dict, ttl: float, fetch: Fetch | None = None) -> dict:
    """GET /data/<endpoint>/data.json and return the ``data`` object (cached)."""
    q = {**params, "sourceapp": sourceapp()}
    key = endpoint + "|" + "&".join(f"{k}={q[k]}" for k in sorted(q) if k != "sourceapp")
    cache = _cache(ttl)
    hit = cache.get(key)
    if hit is not None:
        return hit
    f = fetch or fetch_json
    try:
        doc = await f(f"{RIPESTAT_URL}/{endpoint}/data.json", q, RIPESTAT_TIMEOUT)
    except FetchError as exc:
        raise RipeStatError(f"RIPEstat {endpoint}: {exc}") from exc
    if not isinstance(doc, dict):
        raise RipeStatError(f"RIPEstat {endpoint}: unexpected response")
    if doc.get("status", "ok") != "ok":
        msgs = "; ".join(str(m[-1]) if isinstance(m, (list, tuple)) and m else str(m)
                         for m in (doc.get("messages") or [])[:2])
        raise RipeStatError(f"RIPEstat {endpoint}: status {doc.get('status')} {msgs}".strip())
    data = doc.get("data")
    if not isinstance(data, dict):
        raise RipeStatError(f"RIPEstat {endpoint}: no data")
    cache.set(key, data)
    return data


# --- input helpers -----------------------------------------------------------------------
def parse_asn(asn: Any) -> int:
    m = re.fullmatch(r"(?:AS)?(\d{1,10})", str(asn).strip(), re.I)
    if not m or int(m[1]) > 4294967295:
        raise ValueError(f"invalid ASN: {asn!r}")
    return int(m[1])


def norm_resource(res: str) -> str:
    """Canonical text for an IP or prefix (host bits cleared); ASNs come back as 'AS123'."""
    s = str(res).strip()
    if re.fullmatch(r"(?:AS)?\d{1,10}", s, re.I):
        return f"AS{parse_asn(s)}"
    try:
        if "/" in s:
            return str(ipaddress.ip_network(s, strict=False))
        return str(ipaddress.ip_address(s))
    except ValueError as exc:
        raise ValueError(f"invalid resource: {res!r}") from exc


def family(prefix: str) -> int:
    return 6 if ":" in prefix else 4


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _name_from_holder(holder: str | None) -> str | None:
    if not holder:
        return None
    return holder.split(" - ", 1)[1].strip() if " - " in holder else holder


# --- wrappers ----------------------------------------------------------------------------
async def as_overview(asn: Any, fetch: Fetch | None = None) -> dict:
    n = parse_asn(asn)
    d = await call("as-overview", {"resource": f"AS{n}"}, TTL_LONG, fetch)
    holder = d.get("holder")
    return {"asn": n, "holder": holder, "name": _name_from_holder(holder),
            "announced": bool(d.get("announced")), "block": (d.get("block") or {}).get("desc")}


async def announced_prefixes(asn: Any, fetch: Fetch | None = None) -> dict:
    n = parse_asn(asn)
    d = await call("announced-prefixes", {"resource": f"AS{n}"}, TTL_MID, fetch)
    out = []
    for p in d.get("prefixes") or []:
        pfx = p.get("prefix")
        if not pfx:
            continue
        tl = p.get("timelines") or []
        starts = [t.get("starttime") for t in tl if t.get("starttime")]
        ends = [t.get("endtime") for t in tl if t.get("endtime")]
        out.append({"prefix": pfx, "family": family(pfx),
                    "first_seen": min(starts) if starts else None, "last_seen": max(ends) if ends else None})
    out.sort(key=lambda x: (x["family"], ipaddress.ip_network(x["prefix"], strict=False).prefixlen, x["prefix"]))
    return {"asn": n, "count": len(out), "v4": sum(1 for x in out if x["family"] == 4),
            "v6": sum(1 for x in out if x["family"] == 6), "prefixes": out}


def classify_neighbours(raw: list[dict]) -> dict:
    """RIPEstat 'left' = upstream (towards the collectors), 'right' = downstream, else uncertain.
    Each list is sorted by power (descending)."""
    roles = {"left": "upstream", "right": "downstream"}
    out: dict[str, list] = {"upstreams": [], "downstreams": [], "uncertain": []}
    for n in raw or []:
        asn = _int(n.get("asn"))
        if asn is None:
            continue
        role = roles.get(n.get("type"), "uncertain")
        item = {"asn": asn, "type": n.get("type"), "role": role, "power": _int(n.get("power")) or 0,
                "v4_peers": _int(n.get("v4_peers")) or 0, "v6_peers": _int(n.get("v6_peers")) or 0}
        out[{"upstream": "upstreams", "downstream": "downstreams"}.get(role, "uncertain")].append(item)
    for lst in out.values():
        lst.sort(key=lambda x: (-x["power"], x["asn"]))
    return out


async def asn_neighbours(asn: Any, fetch: Fetch | None = None) -> dict:
    n = parse_asn(asn)
    d = await call("asn-neighbours", {"resource": f"AS{n}"}, TTL_MID, fetch)
    cls = classify_neighbours(d.get("neighbours") or [])
    counts = d.get("neighbour_counts") or {}
    return {"asn": n, "counts": {"left": counts.get("left", len(cls["upstreams"])),
                                 "right": counts.get("right", len(cls["downstreams"])),
                                 "uncertain": counts.get("uncertain", len(cls["uncertain"])),
                                 "unique": counts.get("unique")}, **cls}


def _rpki_state(status: str | None, roas: list[dict]) -> tuple[str, str | None]:
    s = (status or "unknown").lower()
    if s.startswith("invalid"):
        reason = {"invalid_asn": "asn", "invalid_length": "length"}.get(s)
        if reason is None:
            vs = {r.get("validity") for r in roas}
            reason = "asn" if "invalid_asn" in vs else "length" if "invalid_length" in vs else None
        return "invalid", reason
    if s == "valid":
        return "valid", None
    return "unknown", None


async def rpki_validation(asn: Any, prefix: str, fetch: Fetch | None = None) -> dict:
    n = parse_asn(asn)
    pfx = norm_resource(prefix)
    d = await call("rpki-validation", {"resource": f"AS{n}", "prefix": pfx}, TTL_MID, fetch)
    roas = [{"origin": _int(r.get("origin")), "prefix": r.get("prefix"), "max_length": _int(r.get("max_length")),
             "validity": r.get("validity")} for r in (d.get("validating_roas") or [])]
    state, reason = _rpki_state(d.get("status"), roas)
    return {"asn": n, "prefix": pfx, "state": state, "reason": reason, "roas": roas, "validator": d.get("validator")}


def _spec(items: list) -> list[dict]:
    out = []
    for it in items or []:
        if isinstance(it, dict):
            if it.get("prefix"):
                out.append({"prefix": it["prefix"], "origin": _int(it.get("origin"))})
        elif isinstance(it, str):
            out.append({"prefix": it, "origin": None})
    return out


def _vis(v: dict | None) -> dict:
    seeing = _int((v or {}).get("ris_peers_seeing")) or 0
    total = _int((v or {}).get("total_ris_peers")) or 0
    return {"seeing": seeing, "total": total, "pct": round(100 * seeing / total, 1) if total else None}


async def routing_status(resource: str, fetch: Fetch | None = None) -> dict:
    res = norm_resource(resource)
    d = await call("routing-status", {"resource": res}, TTL_SHORT, fetch)
    vis = d.get("visibility") or {}
    origins: list[int] = []
    for o in d.get("origins") or []:
        v = _int(o.get("origin") if isinstance(o, dict) else o)
        if v is not None and v not in origins:
            origins.append(v)
    return {"resource": res, "visibility": {"v4": _vis(vis.get("v4")), "v6": _vis(vis.get("v6"))},
            "first_seen": d.get("first_seen"), "last_seen": d.get("last_seen"), "origins": origins,
            "less_specifics": _spec(d.get("less_specifics"))[:100],
            "more_specifics": _spec(d.get("more_specifics"))[:200],
            "more_specifics_total": len(d.get("more_specifics") or [])}


async def visibility(prefix: str, fetch: Fetch | None = None) -> dict:
    """Per RIS collector: how many full-table peers see the prefix (counted for its own family)."""
    res = norm_resource(prefix)
    d = await call("visibility", {"resource": res}, TTL_SHORT, fetch)
    fam = family(res)
    out = []
    for v in d.get("visibilities") or []:
        p = v.get("probe") or {}
        total = _int(v.get(f"ipv{fam}_full_table_peer_count")) or 0
        missing = len(v.get(f"ipv{fam}_full_table_peers_not_seeing") or [])
        seen = max(total - missing, 0)
        out.append({"id": str(p.get("name") or "").lower(), "ixp": p.get("ixp"), "city": p.get("city"),
                    "country": p.get("country"), "lat": p.get("latitude"), "lon": p.get("longitude"),
                    "seen": seen, "total": total, "is_seen": seen > 0})
    return {"resource": res, "family": fam, "collectors": out}


async def prefix_overview(resource: str, fetch: Fetch | None = None) -> dict:
    res = norm_resource(resource)
    d = await call("prefix-overview", {"resource": res}, TTL_SHORT, fetch)
    return {"resource": res, "announced": bool(d.get("announced")),
            "asns": [{"asn": _int(a.get("asn")), "holder": a.get("holder")} for a in d.get("asns") or []],
            "block": (d.get("block") or {}).get("desc"), "is_less_specific": bool(d.get("is_less_specific")),
            "related_prefixes": [r if isinstance(r, str) else r.get("prefix")
                                 for r in (d.get("related_prefixes") or [])][:50]}


def _path(s: str | None) -> list[int]:
    out = []
    for tok in (s or "").replace("{", " ").replace("}", " ").replace(",", " ").split():
        v = _int(tok)
        if v is not None:
            out.append(v)
    return out


async def looking_glass(prefix: str, fetch: Fetch | None = None) -> dict:
    res = norm_resource(prefix)
    d = await call("looking-glass", {"resource": res}, TTL_SHORT, fetch)
    rrcs = []
    for r in d.get("rrcs") or []:
        peers = []
        for p in (r.get("peers") or [])[:60]:
            path = _path(p.get("as_path"))
            if path:
                peers.append({"peer": p.get("peer"), "origin_asn": _int(p.get("asn_origin")) or path[-1],
                              "as_path": path, "prefix": p.get("prefix"), "last_updated": p.get("last_updated")})
        rrcs.append({"rrc": str(r.get("rrc") or "").lower(), "location": r.get("location"), "peers": peers})
    return {"resource": res, "rrcs": rrcs}


async def routing_history(resource: str, days: int = 30, fetch: Fetch | None = None) -> dict:
    res = norm_resource(resource)
    start = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).strftime("%Y-%m-%d")
    d = await call("routing-history", {"resource": res, "starttime": start}, TTL_MID, fetch)
    origins, timeline = [], []
    for o in d.get("by_origin") or []:
        org = _int(o.get("origin"))
        starts, ends = [], []
        for p in o.get("prefixes") or []:
            for t in p.get("timelines") or []:
                s, e = t.get("starttime"), t.get("endtime")
                if not s:
                    continue
                starts.append(s)
                ends.append(e or s)
                timeline.append({"origin": org, "prefix": p.get("prefix"), "start": s, "end": e,
                                 "peers": _int(t.get("full_peers_seeing"))})
        origins.append({"origin": org, "first": min(starts) if starts else None, "last": max(ends) if ends else None})
    timeline.sort(key=lambda x: (x["start"], x["origin"] or 0))
    return {"resource": res, "days": days, "origins": origins, "timeline": timeline[:300]}


async def geoloc(ip: str, fetch: Fetch | None = None) -> dict:
    res = norm_resource(ip)
    d = await call("maxmind-geo-lite", {"resource": res}, TTL_LONG, fetch)
    best, cover = None, None
    for lr in d.get("located_resources") or []:
        for loc in lr.get("locations") or []:
            if best is None or (loc.get("covered_percentage") or 0) > (best.get("covered_percentage") or 0):
                best, cover = loc, (loc.get("resources") or [lr.get("resource")])[0]
    if not best:
        return {"ip": res, "known": False, "country": None, "city": None, "lat": None, "lon": None, "resource": None}
    lat, lon = best.get("latitude"), best.get("longitude")
    cc = best.get("country")
    known = bool(cc) and cc != "?" and bool(lat or lon)   # anycast/unknown comes back as '?' and 0,0
    return {"ip": res, "known": known, "country": cc if cc != "?" else None, "city": best.get("city") or None,
            "lat": lat if known else None, "lon": lon if known else None, "resource": cover}


async def network_info(ip: str, fetch: Fetch | None = None) -> dict:
    res = norm_resource(ip)
    d = await call("network-info", {"resource": res}, TTL_LONG, fetch)
    return {"ip": res, "prefix": d.get("prefix"),
            "asns": [a for a in (_int(x) for x in d.get("asns") or []) if a is not None]}


_WHOIS_KEYS = ("aut-num", "as-name", "descr", "org", "country", "admin-c", "tech-c", "remarks", "source",
               "orgname", "org-name", "netname")


async def whois_asn(asn: Any, fetch: Fetch | None = None) -> dict:
    n = parse_asn(asn)
    d = await call("whois", {"resource": f"AS{n}"}, TTL_LONG, fetch)
    flat: list[dict] = []
    for rec in d.get("records") or []:
        for kv in rec if isinstance(rec, list) else [rec]:
            if isinstance(kv, dict) and str(kv.get("key", "")).lower() in _WHOIS_KEYS:
                flat.append({"key": kv["key"].lower(), "value": str(kv.get("value", ""))[:200]})

    def first(k: str) -> str | None:
        return next((r["value"] for r in flat if r["key"] == k), None)

    return {"asn": n, "as_name": first("as-name"), "descr": first("descr"), "country": first("country"),
            "org": first("org") or first("orgname") or first("org-name"),
            "authorities": d.get("authorities") or [], "records": flat[:40]}


async def whois_prefix(resource: str, fetch: Fetch | None = None) -> dict:
    """Registry records of an IP/prefix: {'records': [[{key, value}]], 'irr_records': [...], 'authorities': [...]}."""
    res = norm_resource(resource)
    d = await call("whois", {"resource": res}, TTL_LONG, fetch)

    def clean(groups: Any, cap: int) -> list[list[dict]]:
        out = []
        for rec in (groups or [])[:cap]:
            rows = [{"key": str(kv["key"]).strip(), "value": str(kv.get("value", ""))[:500]}
                    for kv in (rec if isinstance(rec, list) else [rec])
                    if isinstance(kv, dict) and kv.get("key")][:60]
            if rows:
                out.append(rows)
        return out

    return {"resource": res, "records": clean(d.get("records"), 8), "irr_records": clean(d.get("irr_records"), 20),
            "authorities": [str(a) for a in (d.get("authorities") or [])][:5]}


async def abuse_contact(resource: str, fetch: Fetch | None = None) -> dict:
    res = norm_resource(resource)
    d = await call("abuse-contact-finder", {"resource": res}, TTL_LONG, fetch)
    emails = [str(e) for e in (d.get("abuse_contacts") or []) if e]
    return {"resource": res, "email": emails[0] if emails else None, "emails": emails[:5],
            "rir": (str(d["authoritative_rir"]).upper() if d.get("authoritative_rir") else None)}


async def rir_stats_country(resource: Any, fetch: Fetch | None = None) -> dict:
    """ASN/IP -> registered country; a 2-letter country code -> counts of its RIR resources."""
    s = str(resource).strip()
    is_cc = bool(re.fullmatch(r"[A-Za-z]{2}", s))
    res = s.upper() if is_cc else norm_resource(s)
    d = await call("rir-stats-country", {"resource": res}, TTL_LONG, fetch)
    located = d.get("located_resources") or []
    if located:
        return {"resource": res, "country": located[0].get("location")}
    r = d.get("resources") or {}
    return {"resource": res, "country": res if is_cc else None,
            "counts": {k: len(v) for k, v in r.items() if isinstance(v, list)},
            "sample": {k: v[:20] for k, v in r.items() if isinstance(v, list)}}
