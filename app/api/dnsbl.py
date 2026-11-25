"""DNS blocklist check (IP or domain), streamed as NDJSON: one line per list, then a summary line.

Line shapes (application/x-ndjson):
  {"type": "list", "row": {name, zone, status, listed, code, reason, delist_url, note, ms, ...}, "done": 3, "total": 38}
  {"type": "summary", "result": {check: "dnsbl", status, score, summary, findings[], data{rows, counts}}}
  {"type": "error", "status": 503, "message": "..."}      (only if the run could not complete)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api._common import guarded_stream, ndjson_response
from app.core import cooldown, dnsbl
from app.core.cache import TTLCache
from app.core.config import HEAVY_RATE_PER_MIN, MAX_CONCURRENT_NET
from app.core.ratelimit import Gate, TokenBucket, limiter
from app.core.turnstile import require_pass
from app.core.validate import ValidationError

router = APIRouter(prefix="/dnsbl", tags=["blacklist"])
_gate = Gate(MAX_CONCURRENT_NET, "Blocklist")
_bucket = TokenBucket(HEAVY_RATE_PER_MIN, 3)
_dep = limiter(lambda: _bucket, "blocklist", HEAVY_RATE_PER_MIN)
_cache = TTLCache(180)


class DnsblRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, examples=["8.8.8.8"])


@router.post("/check", dependencies=[Depends(require_pass), Depends(_dep)])
async def check(req: DnsblRequest, request: Request):
    """Query every DNS blocklist for a public IP or a domain; results stream in as each list answers."""
    try:
        kind, target = dnsbl.classify(req.target)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    cooldown.check(target)
    total = sum(1 for e in dnsbl.load_lists() if e["type"] == kind)

    async def produce():
        rows = _cache.get(target)
        if rows is not None:
            for i, row in enumerate(rows, 1):
                yield {"type": "list", "row": row, "done": i, "total": len(rows), "cached": True}
        else:
            rows = []
            async for row in dnsbl.iter_check(target):
                rows.append(row)
                yield {"type": "list", "row": row, "done": len(rows), "total": total}
            _cache.set(target, rows)
        yield {"type": "summary", "result": dnsbl.summarize(target, kind, rows).to_dict()}

    return ndjson_response(guarded_stream(_gate, produce))
