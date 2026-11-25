"""POST /pass: exchange a Turnstile token for a signed tool pass (see app/core/turnstile.py)."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core import config, turnstile
from app.core.ratelimit import TokenBucket, client_ip, limiter

router = APIRouter(tags=["pass"])
_bucket = TokenBucket(config.PASS_RATE_PER_MIN)
_dep = limiter(lambda: _bucket, "pass", config.PASS_RATE_PER_MIN)


class PassRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=4096)


@router.post("/pass", dependencies=[Depends(_dep)])
async def issue(req: PassRequest, request: Request) -> dict:
    """Verify a Cloudflare Turnstile token and return a 15-minute pass for the X-Tools-Pass header."""
    if not turnstile.enabled():
        raise HTTPException(status_code=404, detail="Turnstile is not enabled on this server.")
    ip = client_ip(request)
    try:
        ok = await turnstile.verify(req.token, ip)
    except (httpx.HTTPError, ValueError):
        raise HTTPException(status_code=503, detail="Could not reach the verification service; try again shortly.",
                            headers={"Retry-After": "5"})
    if not ok:
        raise HTTPException(status_code=403, detail="Challenge failed; reload the page and try again.")
    return {"pass": turnstile.issue_pass(ip, request.headers.get("user-agent", "")), "expires_in": config.PASS_TTL}
