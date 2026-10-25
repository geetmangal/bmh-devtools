"""Tiny in-memory token bucket keyed by client IP (first X-Forwarded-For hop)."""
from __future__ import annotations

import time
from collections import defaultdict

from fastapi import HTTPException, Request

from app.core.config import RATE_LIMIT_PER_MIN


class TokenBucket:
    def __init__(self, rate_per_min: int, burst: int | None = None) -> None:
        self.rate = rate_per_min / 60.0
        self.burst = burst or rate_per_min
        self._buckets: dict[str, tuple[float, float]] = defaultdict(lambda: (self.burst, time.monotonic()))
        self._last_sweep = time.monotonic()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets[key]
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1, now)
        if now - self._last_sweep > 300:
            self._sweep(now)
        return True

    def _sweep(self, now: float) -> None:
        self._last_sweep = now
        stale = [k for k, (_, last) in self._buckets.items() if now - last > 600]
        for k in stale:
            del self._buckets[k]


_bucket = TokenBucket(RATE_LIMIT_PER_MIN)


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request) -> None:
    """FastAPI dependency: 429 when the per-IP bucket is empty."""
    if not _bucket.allow(client_ip(request)):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: 30 requests per minute per IP.")
