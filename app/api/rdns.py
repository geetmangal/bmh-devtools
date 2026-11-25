"""Reverse DNS (PTR) lookup with forward-confirmed reverse DNS (FCrDNS) check."""
from __future__ import annotations

import asyncio
import ipaddress
import re

import dns.asyncresolver
import dns.exception
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api._common import with_cache
from app.core.cache import TTLCache
from app.core.config import (DNS_TIMEOUT, MAX_CONCURRENT_NET, NET_RATE_PER_MIN, RDNS_GUIDE_PUBLISHED, RDNS_GUIDE_URL,
                             RESULT_CACHE_TTL)
from app.core.ratelimit import Gate, TokenBucket, limiter
from app.core.target import TargetError, parse_target
from app.core.validate import normalise_hostname, ValidationError

router = APIRouter(prefix="/rdns", tags=["reverse-dns"])
_gate = Gate(MAX_CONCURRENT_NET, "Reverse DNS")
_bucket = TokenBucket(NET_RATE_PER_MIN)
_dep = limiter(lambda: _bucket, "WHOIS/rDNS", NET_RATE_PER_MIN)
_cache = TTLCache(RESULT_CACHE_TTL)
RESOLVERS = ["1.1.1.1", "8.8.8.8"]
MAX_PTR = 5

MAIL_NOTE = ("Mail servers (Gmail, Outlook, Yahoo and others) expect the sending IP to have a PTR record whose "
             "hostname resolves back to the same IP (FCrDNS). Without it, mail is often rejected or sent to spam. "
             "The PTR record is set by whoever owns the IP block, so on a VPS or cloud server you set it in the "
             "control panel or ask the provider.")


class RdnsRequest(BaseModel):
    ip: str = Field(..., min_length=2, max_length=64, examples=["8.8.8.8"])


def _resolver() -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = list(RESOLVERS)
    r.lifetime = DNS_TIMEOUT * 2
    return r


async def _ptr(ip: str) -> tuple[list[str], str]:
    rev = ipaddress.ip_address(ip).reverse_pointer
    try:
        ans = await _resolver().resolve(rev, "PTR")
        return sorted({rr.target.to_text().rstrip(".").lower() for rr in ans})[:MAX_PTR], "ok"
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "no_ptr"
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return [], "error"
    except dns.exception.DNSException:
        return [], "error"


async def _forward(name: str, want_v6: bool) -> list[str]:
    out: list[str] = []
    for rtype in ("AAAA",) if want_v6 else ("A",):
        try:
            ans = await _resolver().resolve(name, rtype)
            out.extend(str(ipaddress.ip_address(rr.to_text())) for rr in ans)
        except dns.exception.DNSException:
            pass
    return sorted(set(out))


def looks_generic(ptr: str, ip: str) -> bool:
    """True when the PTR just embeds the IP (e.g. 203-0-113-9.isp.net): typical ISP default, poor for mail."""
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        octets = ip.split(".")
        return bool(re.search(r"(?<!\d)" + r"[-.x]".join(octets) + r"(?!\d)", ptr) or
                    re.search(r"(?<!\d)" + r"[-.x]".join(reversed(octets)) + r"(?!\d)", ptr))
    return a.exploded.replace(":", "").lower() in ptr.replace("-", "").replace(".", "").lower()


async def check(ip: str) -> dict:
    ptrs, status = await _ptr(ip)
    v6 = ipaddress.ip_address(ip).version == 6
    records = []
    for name in ptrs:
        try:
            normalise_hostname(name)
            fwd = await _forward(name, v6)
        except ValidationError:
            fwd = []
        records.append({"hostname": name, "forward_ips": fwd[:10], "forward_confirmed": ip in fwd,
                        "generic": looks_generic(name, ip)})
    fcrdns = any(r["forward_confirmed"] for r in records)
    if status == "ok":
        summary = ("PTR is set and forward-confirmed (FCrDNS passes)." if fcrdns else
                   "PTR is set but its hostname does not resolve back to this IP (FCrDNS fails).")
    elif status in ("nxdomain", "no_ptr"):
        summary = "No PTR record is published for this IP."
    else:
        summary = "The reverse lookup failed (resolver timeout); try again."
    return {"ip": ip, "reverse_name": ipaddress.ip_address(ip).reverse_pointer, "status": status,
            "ptr": records, "fcrdns": fcrdns, "summary": summary, "mail_note": MAIL_NOTE,
            "guide_url": RDNS_GUIDE_URL if RDNS_GUIDE_PUBLISHED else None}


@router.post("/lookup", dependencies=[Depends(_dep)])
async def rdns_lookup(req: RdnsRequest) -> dict:
    """PTR record of a public IPv4/IPv6 address plus a forward-confirmed reverse DNS check."""
    try:
        value, is_ip = parse_target(req.ip)
    except TargetError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    if not is_ip:
        raise HTTPException(status_code=422, detail="Enter an IPv4 or IPv6 address (not a hostname)")
    hit, age = _cache.get_with_age(value)
    if hit is not None:
        return with_cache(hit, True, age)
    if hit is None:
        async with _gate.slot():
            hit = await asyncio.wait_for(check(value), DNS_TIMEOUT * 12)
        if hit["status"] != "error":
            _cache.set(value, hit)
    return with_cache(hit, False)
