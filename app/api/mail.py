"""Email DNS checks: MX, SPF, DMARC, DKIM, BIMI, MTA-STS and a full DNS record view.

Every endpoint answers with the common mail-check shape
``{check, target, status, score, summary, findings[], data, timings_ms}`` (see app/core/mailcheck/models.py).
These only read public DNS, so they are light (per-IP limit only). The one exception is DKIM without a selector:
it probes ~30 common selector names, so it needs the tool pass and the per-target cooldown.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field

from app.api._common import DomainRequest, valid_domain
from app.core import cooldown
from app.core.cache import TTLCache
from app.core.config import HEAVY_RATE_PER_MIN, MAIL_RATE_PER_MIN, MAX_CONCURRENT_NET
from app.core.mailcheck import bimi, dkim, dmarc, dnsrec, mta_sts, mx, spf
from app.core.mailcheck.models import CheckResult
from app.core.ratelimit import Gate, TokenBucket, client_ip, limiter
from app.core.turnstile import require_pass
from app.core.validate import ValidationError

router = APIRouter(prefix="/mail", tags=["email"])
_gate = Gate(MAX_CONCURRENT_NET, "Email DNS")
_bucket = TokenBucket(MAIL_RATE_PER_MIN)
_probe_bucket = TokenBucket(HEAVY_RATE_PER_MIN, 3)
_dep = limiter(lambda: _bucket, "email check", MAIL_RATE_PER_MIN)
_cache = TTLCache(120)


class DkimRequest(DomainRequest):
    selector: str | None = Field(None, max_length=63, examples=["google"])


async def _single(kind: str, fn: Callable[[str], Awaitable[CheckResult]], domain: str, extra: str = "") -> dict:
    key = f"{kind}|{domain}|{extra}"
    hit = _cache.get(key)
    if hit is None:
        async with _gate.slot():
            try:
                res = await fn(domain)
            except ValidationError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        hit = res.to_dict()
        if hit["status"] != "error":
            _cache.set(key, hit)
    return hit


@router.post("/mx", dependencies=[Depends(_dep)])
async def mx_lookup(req: DomainRequest) -> dict:
    """MX records -> addresses -> PTR with forward-confirmed reverse DNS, plus the mail provider."""
    return await _single("mx", lambda d: mx.check(d), valid_domain(req.domain))


@router.post("/spf", dependencies=[Depends(_dep)])
async def spf_check(req: DomainRequest) -> dict:
    """Parse the SPF record, expand includes, count the 10 DNS lookups."""
    return await _single("spf", lambda d: spf.check(d), valid_domain(req.domain))


@router.post("/dmarc", dependencies=[Depends(_dep)])
async def dmarc_check(req: DomainRequest) -> dict:
    """DMARC policy, alignment, reports and a staged rollout plan."""
    return await _single("dmarc", lambda d: dmarc.check(d), valid_domain(req.domain))


@router.post("/bimi", dependencies=[Depends(_dep)])
async def bimi_check(req: DomainRequest) -> dict:
    return await _single("bimi", lambda d: bimi.check(d), valid_domain(req.domain))


@router.post("/mta-sts", dependencies=[Depends(_dep)])
async def mta_sts_check(req: DomainRequest) -> dict:
    return await _single("mta_sts", lambda d: mta_sts.check(d), valid_domain(req.domain))


@router.post("/dns", dependencies=[Depends(_dep)])
async def dns_records(req: DomainRequest) -> dict:
    """All common record types, nameserver health, SOA timers, CAA and the DNSSEC state."""
    return await _single("dnsrec", lambda d: dnsrec.check(d), valid_domain(req.domain))


@router.post("/dkim", dependencies=[Depends(_dep)])
async def dkim_check(req: DkimRequest, request: Request) -> dict:
    """One selector (light), or no selector: probe the common selector names (heavy: tool pass + cooldown)."""
    domain = valid_domain(req.domain)
    selector = (req.selector or "").strip().lower().rstrip(".") or None
    if selector is None:
        await require_pass(request)
        if not _probe_bucket.allow(client_ip(request)):
            raise HTTPException(status_code=429, detail=f"Rate limit exceeded: {HEAVY_RATE_PER_MIN} DKIM probes per minute per IP.",
                                headers={"Retry-After": "10"})
        cooldown.check(domain)
    return await _single("dkim", lambda d: dkim.check(d, selector), domain, selector or "*")
