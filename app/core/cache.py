"""Tiny in-process TTL cache (bounded) for third-party lookups (RDAP, RIPEstat, PTR)."""
from __future__ import annotations

import time
from typing import Any


class TTLCache:
    def __init__(self, ttl: float, max_entries: int = 512) -> None:
        self.ttl = ttl
        self.max = max_entries
        self._d: dict[str, tuple[float, Any, float]] = {}  # key -> (expires, value, inserted)

    def get(self, key: str) -> Any | None:
        item = self._d.get(key)
        if item is None:
            return None
        if item[0] < time.monotonic():
            self._d.pop(key, None)
            return None
        return item[1]

    def get_with_age(self, key: str) -> tuple[Any | None, int]:
        """(value, age in whole seconds since it was stored); (None, 0) on a miss or expiry."""
        item = self._d.get(key)
        if item is None:
            return None, 0
        if item[0] < time.monotonic():
            self._d.pop(key, None)
            return None, 0
        return item[1], max(0, int(time.monotonic() - item[2]))

    def set(self, key: str, value: Any) -> None:
        if len(self._d) >= self.max:
            now = time.monotonic()
            for k in [k for k, (exp, _, _i) in self._d.items() if exp < now]:
                del self._d[k]
            while len(self._d) >= self.max:  # still full: drop the oldest insert
                self._d.pop(next(iter(self._d)))
        now = time.monotonic()
        self._d[key] = (now + self.ttl, value, now)
