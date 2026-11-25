"""IRR Explorer client: route objects in every IRR registry (plus RPKI-derived ones) for a prefix.

GET https://irrexplorer.nlnog.net/api/prefixes/prefix/<prefix> answers a list with the prefix itself and its
covering / more-specific prefixes. We keep the exact entry and the covering ones, compare the origins in the
route objects with the origin(s) seen in BGP and produce a verdict: match | mismatch | missing | unknown.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any, Awaitable, Callable

from app.core.cache import TTLCache
from app.core.config import RESULT_CACHE_TTL
from app.core.httpjson import FetchError, fetch_json

Fetch = Callable[..., Awaitable[Any]]

BASE = os.environ.get("BMH_TOOLS_IRREXPLORER_URL", "https://irrexplorer.nlnog.net/api/prefixes/prefix").rstrip("/")
TTL = min(1800.0, float(RESULT_CACHE_TTL))
TIMEOUT = 8.0
MAX_OBJECTS = 40
MAX_MESSAGES = 10
RPSL_MAX = 1500
_cache = TTLCache(TTL, max_entries=512)


class IrrError(Exception):
    """IRR Explorer unreachable or answered something unusable."""


def clear_cache() -> None:
    _cache._d.clear()


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


async def lookup(prefix: str, fetch: Fetch | None = None) -> list[dict]:
    """Raw IRR Explorer entries for ``prefix`` (cached 30 min)."""
    key = str(prefix)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    f = fetch or fetch_json
    try:
        doc = await f(f"{BASE}/{prefix}", None, TIMEOUT)
    except FetchError as exc:
        raise IrrError(f"IRR Explorer: {exc}") from exc
    if not isinstance(doc, list):
        raise IrrError("IRR Explorer: unexpected response")
    entries = [e for e in doc if isinstance(e, dict) and e.get("prefix")]
    _cache.set(key, entries)
    return entries


def _net(p: Any):
    try:
        return ipaddress.ip_network(str(p), strict=False)
    except ValueError:
        return None


def _rel(entry_prefix: str, target) -> str | None:
    """'exact' | 'covering' | None (more-specific or unrelated)."""
    n = _net(entry_prefix)
    if n is None or target is None or n.version != target.version:
        return None
    if n == target:
        return "exact"
    if n.prefixlen < target.prefixlen and target.subnet_of(n):
        return "covering"
    return None


def build(entries: list[dict] | None, prefix: str, bgp_origins: list[int]) -> dict:
    """Contract object for ``validation.irr`` plus the verdict under key ``verdict`` (not part of the JSON contract;
    callers move it to ``validation.summary.irr``)."""
    if entries is None:
        return {"available": False, "sources": [], "objects": [], "rpki_routes": [], "messages": [], "category": None,
                "verdict": "unknown", "rir": None}
    target = _net(prefix)
    objects: list[dict] = []
    rpki_routes: list[dict] = []
    sources: set[str] = set()
    messages: list[dict] = []
    category: str | None = None
    rir: str | None = None
    seen_rpki: set[tuple] = set()
    origin_set = set(bgp_origins)
    for e in entries:
        rel = _rel(e.get("prefix"), target)
        if rel is None:
            continue
        exact = rel == "exact"
        if exact or rir is None:
            rir = e.get("rir") or rir
        for r in e.get("rpkiRoutes") or []:
            asn = _int(r.get("asn"))
            k = (e["prefix"], asn, r.get("rpkiMaxLength"))
            if asn is None or k in seen_rpki:
                continue
            seen_rpki.add(k)
            rpki_routes.append({"prefix": e["prefix"], "asn": asn, "max_length": _int(r.get("rpkiMaxLength"))})
        for source, routes in sorted((e.get("irrRoutes") or {}).items()):
            for r in routes or []:
                asn = _int(r.get("asn"))
                if asn is None:
                    continue
                sources.add(str(source))
                objects.append({"source": str(source), "prefix": e["prefix"], "asn": asn,
                                "rpki_status": r.get("rpkiStatus"), "exact": exact, "matches_bgp": asn in origin_set,
                                "rpsl": str(r.get("rpslText") or "")[:RPSL_MAX]})
        if exact:
            category = e.get("categoryOverall") or category
            for m in e.get("messages") or []:
                if isinstance(m, dict) and m.get("text") and len(messages) < MAX_MESSAGES:
                    messages.append({"category": m.get("category") or "info", "text": str(m["text"])[:300]})
    objects.sort(key=lambda o: (not o["exact"], o["source"], o["asn"]))
    exact_objs = [o for o in objects if o["exact"]]
    relevant = exact_objs or objects          # no object for the exact prefix: covering objects decide
    if not objects:
        verdict = "missing"
    elif not origin_set:
        verdict = "unknown"
    else:
        have = {o["asn"] for o in relevant}
        verdict = "match" if origin_set <= have else "mismatch"
    return {"available": True, "sources": sorted(sources), "objects": objects[:MAX_OBJECTS],
            "rpki_routes": rpki_routes[:MAX_OBJECTS], "messages": messages, "category": category,
            "verdict": verdict, "rir": rir}
