"""Read-only SMTP connection test (banner, EHLO, STARTTLS, TLS and certificate). Never sends mail.

Disabled unless BMH_TOOLS_SMTP_ENABLED=1: outbound port 25 is blocked on the production host. When disabled the
endpoint answers 200 with an info result (data.enabled == false) and the page shows an "unavailable from our
server" card with the commands to run it yourself.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core import cooldown, smtpcheck
from app.core.cache import TTLCache
from app.core.config import HEAVY_RATE_PER_MIN, MAX_CONCURRENT_NET
from app.core.ratelimit import Gate, TokenBucket, limiter
from app.core.target import TargetError, parse_target
from app.core.turnstile import require_pass
from app.core.validate import ValidationError

router = APIRouter(prefix="/smtp", tags=["smtp"])
_gate = Gate(max(2, MAX_CONCURRENT_NET // 2), "SMTP test")
_bucket = TokenBucket(HEAVY_RATE_PER_MIN, 3)
_dep = limiter(lambda: _bucket, "SMTP test", HEAVY_RATE_PER_MIN)
_cache = TTLCache(60)


class SmtpRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253, examples=["mail.example.com"])
    port: Literal[25, 587, 2525] = 25


@router.post("/check", dependencies=[Depends(_dep)])
async def check(req: SmtpRequest, request: Request) -> dict:
    """Connect to the mail server (public hosts only), say EHLO, try STARTTLS, report TLS and the certificate."""
    if not smtpcheck.enabled():
        # Info result, no connection made: no reason to make the visitor solve a challenge first.
        return (await smtpcheck.check(req.host.strip(), req.port)).to_dict()
    await require_pass(request)
    try:
        host, _is_ip = parse_target(req.host)
    except TargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    key = f"{host}|{req.port}"
    hit = _cache.get(key)
    if hit is None:
        cooldown.check(host)
        async with _gate.slot():
            try:
                res = await smtpcheck.check(host, req.port)
            except ValidationError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        hit = res.to_dict()
        if hit["status"] != "error":
            _cache.set(key, hit)
    return hit
