"""Small guarded JSON fetcher for third-party data APIs (RIPEstat, IANA bootstrap, RDAP servers)."""
from __future__ import annotations

import json
from urllib.parse import urlsplit, urljoin

import httpx

from app.core.target import TargetError, parse_target, resolve_public

MAX_BYTES = 768 * 1024
MAX_REDIRECTS = 3


class FetchError(Exception):
    """Upstream unreachable / bad answer. status is the HTTP status to surface (502 default)."""

    def __init__(self, msg: str, status: int = 502) -> None:
        super().__init__(msg)
        self.status = status
        self.not_found = status == 404


async def _guard(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise FetchError("upstream URL refused (https only)")
    try:
        host, is_ip = parse_target(parts.hostname)  # refuses internal IP literals and local names
        if not is_ip:
            await resolve_public(host)  # every A/AAAA must be public
    except TargetError as exc:
        raise FetchError(f"upstream host refused: {exc}") from exc


async def fetch_json(url: str, params: dict | None = None, timeout: float = 8.0, headers: dict | None = None):
    """GET url (https only, public hosts only, <= 3 re-validated redirects, 768 KiB cap) and decode JSON."""
    hdrs = {"Accept": "application/rdap+json, application/json", "User-Agent": "BookMyHost-DevTools/1.2 (+https://bookmyhost.com/tools/)"}
    hdrs.update(headers or {})
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            await _guard(url)
            try:
                async with client.stream("GET", url, params=params, headers=hdrs) as r:
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        url, params = urljoin(url, r.headers["location"]), None
                        continue
                    if r.status_code == 404:
                        raise FetchError("not found", 404)
                    if r.status_code >= 400:
                        raise FetchError(f"upstream returned HTTP {r.status_code}")
                    buf = bytearray()
                    async for chunk in r.aiter_bytes():
                        buf += chunk
                        if len(buf) > MAX_BYTES:
                            raise FetchError("upstream response too large")
            except httpx.HTTPError as exc:
                raise FetchError(f"upstream request failed: {type(exc).__name__}") from exc
            try:
                return json.loads(bytes(buf))
            except ValueError as exc:
                raise FetchError("upstream returned invalid JSON") from exc
    raise FetchError("too many redirects")
