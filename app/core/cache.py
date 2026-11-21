"""Tiny in-process TTL cache (bounded) for third-party lookups (RDAP, RIPEstat, PTR)."""
from __future__ import annotations

import time
from typing import Any


class TTLCache:
    def __init__(self, ttl: float, max_entries: int = 512) -> None:
        self.ttl = ttl
        self.max = max_entries
        self._d: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        item = self._d.get(key)
        if item is None:
            return None
        if item[0] < time.monotonic():
            self._d.pop(key, None)
            return None
        return item[1]

    def set(self, key: str, value: Any) -> None:
        if len(self._d) >= self.max:
            now = time.monotonic()
            for k in [k for k, (exp, _) in self._d.items() if exp < now]:
                del self._d[k]
            while len(self._d) >= self.max:  # still full: drop the oldest insert
                self._d.pop(next(iter(self._d)))
        self._d[key] = (time.monotonic() + self.ttl, value)
