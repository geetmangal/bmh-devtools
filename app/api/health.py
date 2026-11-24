"""Domain health report: every mail/DNS check run concurrently, streamed as NDJSON, then one graded summary.

Line shapes (application/x-ndjson):
  {"type": "check", "name": "spf", "result": {...mail-check shape...}, "elapsed_ms": 412, "done": 3, "total": 10}
  {"type": "summary", "summary": {domain, score, grade, areas[], radar[], capped_by[], fixes[], counts, checks}, "elapsed_ms": 9000}
  {"type": "error", "status": 503, "message": "..."}
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import Field

from app.api._common import DomainRequest, guarded_stream, ndjson_response, valid_domain
from app.core import cooldown
from app.core.cache import TTLCache
from app.core.config import HEALTH_RATE_PER_MIN, MAX_CONCURRENT_HEALTH
from app.core.mailcheck import health
from app.core.ratelimit import Gate, TokenBucket, limiter
from app.core.turnstile import require_pass

router = APIRouter(prefix="/health", tags=["domain-health"])
_gate = Gate(MAX_CONCURRENT_HEALTH, "Domain health")
_bucket = TokenBucket(HEALTH_RATE_PER_MIN, 2)
_dep = limiter(lambda: _bucket, "domain health", HEALTH_RATE_PER_MIN)
_cache = TTLCache(180)


class HealthRequest(DomainRequest):
    dkim_selector: str | None = Field(None, max_length=63)


@router.post("/domain", dependencies=[Depends(require_pass), Depends(_dep)])
async def domain_health(req: HealthRequest, request: Request):
    """Run the full set of checks for a domain and grade it A-F."""
    domain = valid_domain(req.domain)
    selector = (req.dkim_selector or "").strip().lower() or None
    cooldown.check(domain)
    key = f"{domain}|{selector or ''}"

    async def produce():
        events = _cache.get(key)
        if events is None:
            events, done = [], 0
            total = len(health.CHECK_NAMES)
            async for ev in health.iter_health(domain, dkim_selector=selector):
                if ev["type"] == "check":
                    done += 1
                    ev = {**ev, "done": done, "total": total}
                events.append(ev)
                yield ev
            if events and events[-1]["type"] == "summary":
                _cache.set(key, events)
        else:
            for ev in events:
                yield ev

    return ndjson_response(guarded_stream(_gate, produce))
