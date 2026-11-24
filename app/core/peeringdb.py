"""PeeringDB client (net / netixlan / netfac), cached 6 h, anonymous-rate-limit friendly.

At most two requests run at once (module-level semaphore). A 429 never raises: the caller gets
a partial result with ``partial: True`` and a human note. Other failures raise ``PeeringDBError``.
"""
from __future__ import annotations

import asyncio
import os
import weakref
from typing import Any, Awaitable, Callable

from app.core.cache import TTLCache
from app.core.httpjson import FetchError, fetch_json
from app.core.ripestat import parse_asn

Fetch = Callable[..., Awaitable[Any]]

BASE = "https://www.peeringdb.com/api"
TTL = 6 * 3600.0
TIMEOUT = 10.0
RATE_NOTE = "PeeringDB rate limit reached (anonymous API); showing partial data, try again in a minute."
_cache = TTLCache(TTL, max_entries=512)

# Module-level limit of 2 concurrent requests. asyncio primitives bind to a loop on first
# contention, so keep one per running loop (a single one in production, one per test loop).
_sems: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]" = weakref.WeakKeyDictionary()
CONCURRENCY = 2


def _sem() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    if loop not in _sems:
        _sems[loop] = asyncio.Semaphore(CONCURRENCY)
    return _sems[loop]


class PeeringDBError(Exception):
    pass


class RateLimited(PeeringDBError):
    pass


def clear_cache() -> None:
    _cache._d.clear()


def _headers() -> dict:
    key = os.environ.get("PEERINGDB_API_KEY")
    return {"Authorization": f"Api-Key {key}"} if key else {}


async def _get(path: str, params: dict, fetch: Fetch | None = None) -> list[dict]:
    f = fetch or fetch_json
    async with _sem():
        try:
            doc = await f(f"{BASE}/{path}", params, TIMEOUT, _headers())
        except FetchError as exc:
            if "429" in str(exc):
                raise RateLimited(RATE_NOTE) from exc
            if getattr(exc, "not_found", False):
                return []
            raise PeeringDBError(f"PeeringDB {path}: {exc}") from exc
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, list):
        raise PeeringDBError(f"PeeringDB {path}: unexpected response")
    return data


def _partial(asn: int, **extra: Any) -> dict:
    return {"asn": asn, "partial": True, "notes": [RATE_NOTE], **extra}


async def net_by_asn(asn: Any, fetch: Fetch | None = None) -> dict:
    n = parse_asn(asn)
    key = f"net|{n}"
    if (hit := _cache.get(key)) is not None:
        return hit
    try:
        rows = await _get("net", {"asn": n}, fetch)
    except RateLimited:
        return _partial(n, found=None)
    if not rows:
        res = {"asn": n, "found": False, "partial": False, "notes": []}
    else:
        r = rows[0]
        res = {"asn": n, "found": True, "partial": False, "notes": [], "net_id": r.get("id"), "name": r.get("name"),
               "aka": r.get("aka") or None, "website": r.get("website") or None,
               "policy": r.get("policy_general") or None, "policy_url": r.get("policy_url") or None,
               "traffic": r.get("info_traffic") or None, "ratio": r.get("info_ratio") or None,
               "scope": r.get("info_scope") or None, "irr_as_set": r.get("irr_as_set") or None,
               "info_type": r.get("info_type") or None, "prefixes4": r.get("info_prefixes4"),
               "prefixes6": r.get("info_prefixes6"), "ix_count": r.get("ix_count"), "fac_count": r.get("fac_count")}
    _cache.set(key, res)
    return res


async def ix_presence(asn: Any, fetch: Fetch | None = None) -> dict:
    """netixlan rows (one per port). IX city/country need a second lookup (/ix); if that is
    rate-limited the ports are returned without cities and ``partial`` is set."""
    n = parse_asn(asn)
    key = f"ix|{n}"
    if (hit := _cache.get(key)) is not None:
        return hit
    try:
        rows = await _get("netixlan", {"asn": n}, fetch)
    except RateLimited:
        return _partial(n, count=None, unique_ix=None, ixs=[])
    notes: list[str] = []
    ix_ids = sorted({r["ix_id"] for r in rows if r.get("ix_id")})[:150]
    meta: dict[int, dict] = {}
    if ix_ids:
        try:
            for ix in await _get("ix", {"id__in": ",".join(map(str, ix_ids))}, fetch):
                meta[ix.get("id")] = ix
        except RateLimited:
            notes.append(RATE_NOTE)
    ixs = []
    for r in rows[:500]:
        m = meta.get(r.get("ix_id"), {})
        ixs.append({"ix_id": r.get("ix_id"), "name": r.get("name"), "city": m.get("city") or None,
                    "country": m.get("country") or None, "speed": r.get("speed"), "ipaddr4": r.get("ipaddr4"),
                    "ipaddr6": r.get("ipaddr6"), "is_rs_peer": bool(r.get("is_rs_peer")),
                    "operational": r.get("operational", True) is not False and r.get("status", "ok") != "not-operational"})
    ixs.sort(key=lambda x: (-(x["speed"] or 0), x["name"] or ""))
    res = {"asn": n, "count": len(rows), "unique_ix": len({r.get("ix_id") for r in rows}), "ixs": ixs,
           "partial": bool(notes), "notes": notes}
    if not notes:
        _cache.set(key, res)
    return res


async def facilities(asn: Any, fetch: Fetch | None = None) -> dict:
    n = parse_asn(asn)
    key = f"fac|{n}"
    if (hit := _cache.get(key)) is not None:
        return hit
    try:
        rows = await _get("netfac", {"local_asn": n}, fetch)
    except RateLimited:
        return _partial(n, count=None, facilities=[])
    facs = [{"fac_id": r.get("fac_id"), "name": r.get("name"), "city": r.get("city") or None,
             "country": r.get("country") or None} for r in rows[:500]]
    facs.sort(key=lambda x: (x["country"] or "", x["city"] or "", x["name"] or ""))
    res = {"asn": n, "count": len(rows), "facilities": facs, "partial": False, "notes": []}
    _cache.set(key, res)
    return res
