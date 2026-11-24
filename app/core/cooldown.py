"""Per-target cooldown for heavy endpoints.

One shared token bucket keyed by the normalised target (domain, IP, ASN or prefix), at most
TARGET_RATE_PER_MIN runs per minute across ALL clients and ALL heavy endpoints. The per-IP limits stop one
visitor; this stops many visitors (or a botnet) from aiming the toolbox at one victim.
"""
from __future__ import annotations

from fastapi.responses import JSONResponse

from app.core.config import TARGET_RATE_PER_MIN
from app.core.ratelimit import TokenBucket

_bucket = TokenBucket(TARGET_RATE_PER_MIN, TARGET_RATE_PER_MIN)


class TargetBusy(Exception):
    """Raised by check(); main.py turns it into the 429 {"error": "target_busy"} body."""


def norm(target: str) -> str:
    return str(target).strip().strip("[]").rstrip(".").lower()


def check(target: str) -> None:
    """Call AFTER validating the target (a rejected input must not use up the budget)."""
    if not _bucket.allow(norm(target)):
        raise TargetBusy(norm(target))


def busy_response() -> JSONResponse:
    return JSONResponse({"error": "target_busy"}, status_code=429, headers={"Retry-After": "15", "Cache-Control": "no-store"})
