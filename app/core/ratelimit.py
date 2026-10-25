"""Per-IP token bucket (second layer; nginx limit_req is authoritative) and concurrency gates."""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import HTTPException, Request

from app.core.config import QUEUE_WAIT, RATE_LIMIT_PER_MIN


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
    """Client address. The app is reachable only through nginx on 127.0.0.1, which sets
    X-Real-IP from the Cloudflare-verified $remote_addr (real_ip module) and overwrites any
    client-supplied value. X-Forwarded-For is deliberately ignored (clients can prepend to it)."""
    real = (request.headers.get("x-real-ip") or "").strip()
    if real:
        return real
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request) -> None:
    """FastAPI dependency: 429 when the per-IP bucket is empty."""
    if not _bucket.allow(client_ip(request)):
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded: {RATE_LIMIT_PER_MIN} requests per minute per IP.",
                            headers={"Retry-After": "10"})


class Gate:
    """Caps concurrent outbound checks; waits up to QUEUE_WAIT seconds for a slot, then 503."""

    def __init__(self, size: int, name: str) -> None:
        self.size = size
        self.name = name
        self._sem: asyncio.Semaphore | None = None
        self._loop = None

    def _semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._sem is None or self._loop is not loop:
            self._sem, self._loop = asyncio.Semaphore(self.size), loop
        return self._sem

    @asynccontextmanager
    async def slot(self):
        sem = self._semaphore()
        try:
            await asyncio.wait_for(sem.acquire(), QUEUE_WAIT)
        except asyncio.TimeoutError:
            raise HTTPException(status_code=503, detail=f"{self.name} checker is busy, retry in a few seconds.",
                                headers={"Retry-After": "5"})
        try:
            yield
        finally:
            sem.release()
