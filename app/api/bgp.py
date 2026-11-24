"""BGP / ASN / prefix reports (public RIPEstat + PeeringDB data) and the multi-location looking glass (Globalping).

GET  asn/{asn}            ASN report: prefixes, neighbours, RPKI coverage, IX + facilities, AS graph, findings
GET  prefix/{prefix:path} prefix (or IP) report: origin, RPKI, RIS collector visibility, history, AS paths, findings
POST lg/global            ping / traceroute from Globalping probes, streamed as NDJSON:
     {"type": "created", id, probes_count} -> {"type": "probe", index, probe{probe{city,country,lat,lon,..}, stats, hops}}*
     -> {"type": "done" | "timeout" | "error", ...}
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api._common import guarded_stream, ndjson_response
from app.core import bgpview, cooldown, globalping
from app.core.cache import TTLCache
from app.core.config import BGP_RATE_PER_MIN, GLOBAL_LG_RATE_PER_MIN, MAX_CONCURRENT_NET
from app.core.ratelimit import Gate, TokenBucket, limiter
from app.core.ripestat import parse_asn
from app.core.target import TargetError, parse_target
from app.core.turnstile import require_pass

router = APIRouter(tags=["bgp"])
_gate = Gate(MAX_CONCURRENT_NET, "BGP report")
_bucket = TokenBucket(BGP_RATE_PER_MIN, 5)
_dep = limiter(lambda: _bucket, "BGP report", BGP_RATE_PER_MIN)
_gp_gate = Gate(3, "Global looking glass")
_gp_bucket = TokenBucket(GLOBAL_LG_RATE_PER_MIN, 2)
_gp_dep = limiter(lambda: _gp_bucket, "global looking glass", GLOBAL_LG_RATE_PER_MIN)
_asn_cache = TTLCache(300)
_prefix_cache = TTLCache(120)


@router.get("/asn/{asn}", dependencies=[Depends(require_pass), Depends(_dep)])
async def asn_report(asn: str) -> dict:
    """Everything public about one AS number (accepts 13335 or AS13335)."""
    try:
        n = parse_asn(asn)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    key = f"AS{n}"
    hit = _asn_cache.get(key)
    if hit is None:
        cooldown.check(key)
        async with _gate.slot():
            try:
                hit = await bgpview.asn_report(n)
            except bgpview.BgpInputError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        if not hit.get("partial"):
            _asn_cache.set(key, hit)
    return hit


@router.get("/prefix/{prefix:path}", dependencies=[Depends(require_pass), Depends(_dep)])
async def prefix_report(prefix: str) -> dict:
    """Routing view of a public prefix or IP address (1.1.1.0/24 or 1.1.1.1)."""
    try:
        res, _is_ip = bgpview.parse_resource(prefix)
    except bgpview.BgpInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    hit = _prefix_cache.get(res)
    if hit is None:
        cooldown.check(res)
        async with _gate.slot():
            try:
                hit = await bgpview.prefix_report(res)
            except bgpview.BgpInputError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        if not hit.get("partial"):
            _prefix_cache.set(res, hit)
    return hit


class GlobalLgRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, examples=["1.1.1.1"])
    type: Literal["ping", "traceroute"] = "ping"
    preset: Literal["india", "asia", "europe", "north america", "world"] = "india"
    limit: int = Field(6, ge=1, le=10)


@router.post("/lg/global", dependencies=[Depends(require_pass), Depends(_gp_dep)])
async def lg_global(req: GlobalLgRequest, request: Request):
    """Run ping or traceroute from a set of Globalping probes (India, Asia, Europe, North America or world)."""
    try:
        host, _is_ip = parse_target(req.target)
    except TargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    cooldown.check(host)

    async def produce():
        async for ev in globalping.run(req.type, host, req.preset, req.limit):
            ev = dict(ev)
            kind = ev.pop("event")
            if kind in ("done", "timeout"):
                ev.pop("probes", None)  # every probe already streamed as its own line
            yield {**ev, "type": kind}

    return ndjson_response(guarded_stream(_gp_gate, produce))
