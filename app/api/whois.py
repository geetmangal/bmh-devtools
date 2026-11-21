"""WHOIS / RDAP lookup. RDAP (RFC 9082/9083) through the IANA bootstrap registry; port-43 WHOIS is used
only for a TLD that has no RDAP service. Domain, IPv4 and IPv6 targets. Personal data in RDAP entities
is never returned: only registrar / organisation names and abuse contact roles."""
from __future__ import annotations

import asyncio
import ipaddress
import re
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.cache import TTLCache
from app.core.config import MAX_CONCURRENT_NET, NET_RATE_PER_MIN, RDAP_BOOTSTRAP_URL, RDAP_TIMEOUT
from app.core.httpjson import FetchError, fetch_json
from app.core.ratelimit import Gate, TokenBucket, limiter
from app.core.target import TargetError, parse_target, resolve_public

router = APIRouter(prefix="/whois", tags=["whois"])
_gate = Gate(MAX_CONCURRENT_NET, "WHOIS")
_bucket = TokenBucket(NET_RATE_PER_MIN)
_dep = limiter(lambda: _bucket, "WHOIS/rDNS", NET_RATE_PER_MIN)
_cache = TTLCache(300)
_bootstrap = TTLCache(86400, 8)
WHOIS_MAX = 16 * 1024


class WhoisRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=253, examples=["bookmyhost.com"])


async def _bootstrap_services(kind: str) -> list:
    """kind: dns | ipv4 | ipv6 -> list of [[keys], [urls]] from the IANA bootstrap file (cached 24 h)."""
    key = f"bs:{kind}"
    hit = _bootstrap.get(key)
    if hit is None:
        data = await fetch_json(f"{RDAP_BOOTSTRAP_URL}/{kind}.json", None, RDAP_TIMEOUT)
        hit = data.get("services") or []
        _bootstrap.set(key, hit)
    return hit


def _pick_url(urls: list[str]) -> str | None:
    https = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
    return (https[0] if https else None)


async def rdap_base_for_domain(tld: str) -> str | None:
    for keys, urls in await _bootstrap_services("dns"):
        if tld in keys:
            return _pick_url(urls)
    return None


async def rdap_base_for_ip(ip: str) -> str | None:
    addr = ipaddress.ip_address(ip)
    best: tuple[int, str] | None = None
    for keys, urls in await _bootstrap_services("ipv6" if addr.version == 6 else "ipv4"):
        for k in keys:
            try:
                net = ipaddress.ip_network(k, strict=False)
            except ValueError:
                continue
            if net.version == addr.version and addr in net and (best is None or net.prefixlen > best[0]):
                u = _pick_url(urls)
                if u:
                    best = (net.prefixlen, u)
    return best[1] if best else None


def _events(doc: dict) -> dict:
    out = {}
    for e in doc.get("events") or []:
        a, d = str(e.get("eventAction", "")), e.get("eventDate")
        if a and d:
            out[a.replace(" ", "_")[:40]] = str(d)[:40]
    return out


def _vcard_fn(entity: dict) -> str | None:
    """Organisation / display name only (fn, org); never email, phone or address."""
    arr = (entity.get("vcardArray") or [None, []])[1] or []
    for item in arr:
        if isinstance(item, list) and item and item[0] in ("fn", "org") and len(item) >= 4:
            v = item[3]
            if isinstance(v, list):
                v = " ".join(str(x) for x in v)
            if v:
                return str(v)[:120]
    return None


def _entities(doc: dict, depth: int = 0) -> list[dict]:
    res = []
    for e in doc.get("entities") or []:
        roles = [str(r) for r in (e.get("roles") or [])][:6]
        item = {"roles": roles, "handle": str(e.get("handle", ""))[:64] or None, "name": _vcard_fn(e)}
        for pid in e.get("publicIds") or []:
            if str(pid.get("type", "")).lower() == "iana registrar id":
                item["iana_id"] = str(pid.get("identifier", ""))[:16]
        if "registrant" in roles or "administrative" in roles or "technical" in roles:
            item["name"] = None  # registrant / admin / tech are personal data: roles only
        res.append(item)
        if depth < 1:
            res.extend(_entities(e, depth + 1))
    return res[:20]


def summarise_domain(doc: dict) -> dict:
    ns = sorted({str(n.get("ldhName", "")).lower().rstrip(".") for n in doc.get("nameservers") or [] if n.get("ldhName")})
    return {"type": "domain", "name": str(doc.get("ldhName", "")).lower(), "handle": doc.get("handle"),
            "status": [str(s) for s in (doc.get("status") or [])][:20], "events": _events(doc),
            "nameservers": ns[:16], "dnssec": bool((doc.get("secureDNS") or {}).get("delegationSigned")),
            "entities": _entities(doc)}


def _cidrs(doc: dict) -> list[str]:
    out = []
    for c in doc.get("cidr0_cidrs") or []:
        pfx = c.get("v4prefix") or c.get("v6prefix")
        if pfx:
            out.append(f"{pfx}/{c.get('length')}")
    return out[:8]


def summarise_ip(doc: dict) -> dict:
    return {"type": "ip", "name": doc.get("name"), "handle": doc.get("handle"),
            "start": doc.get("startAddress"), "end": doc.get("endAddress"), "ip_version": doc.get("ipVersion"),
            "network_type": doc.get("type"), "country": doc.get("country"),
            "cidr": _cidrs(doc),
            "status": [str(s) for s in (doc.get("status") or [])][:20], "events": _events(doc),
            "entities": _entities(doc), "remarks": [str(r.get("title", ""))[:100] for r in (doc.get("remarks") or [])][:5]}


async def _whois43(host: str, query: str) -> str:
    """Raw WHOIS (RFC 3912). host is resolved and every address must be public; query is a validated
    hostname (letters, digits, dot, hyphen, underscore only), so it cannot carry CR/LF."""
    ips = await resolve_public(host)
    if not re.fullmatch(r"[a-z0-9_.-]{1,253}", query):
        raise FetchError("invalid WHOIS query", 422)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ips[0], 43), 5)
    try:
        writer.write(query.encode("ascii") + b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(WHOIS_MAX), 6)
    finally:
        writer.close()
    return data.decode("utf-8", "replace")


async def whois_fallback(domain: str, tld: str) -> dict:
    iana = await _whois43("whois.iana.org", tld)
    m = re.search(r"^whois:\s*([A-Za-z0-9.-]+)\s*$", iana, re.M | re.I)
    if not m:
        raise HTTPException(status_code=404, detail=f"No RDAP or WHOIS service is published for .{tld}")
    server = m[1].lower()
    try:
        raw = await _whois43(server, domain)
    except (TargetError, OSError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=502, detail=f"WHOIS server {server} failed: {type(exc).__name__}")
    clean = "".join(c if (c in "\n\t" or 32 <= ord(c) < 127) else "?" for c in raw)[:WHOIS_MAX]
    return {"type": "domain", "name": domain, "source": f"whois://{server}", "protocol": "whois", "raw": clean}


async def lookup(query: str) -> dict:
    value, is_ip = parse_target(query)  # public IPs only (private ranges have no public RDAP); safe hostnames
    if is_ip:
        base = await rdap_base_for_ip(value)
        if not base:
            raise HTTPException(status_code=404, detail="No RDAP service found for this address range")
        try:
            doc = await fetch_json(f"{base.rstrip('/')}/ip/{quote(value, safe=':')}", None, RDAP_TIMEOUT)
        except FetchError as exc:
            raise HTTPException(status_code=502 if exc.status != 404 else 404, detail=f"RDAP lookup failed: {exc}")
        return {"query": value, "protocol": "rdap", "source": base, **summarise_ip(doc)}
    labels = value.split(".")
    tld = labels[-1]
    base = await rdap_base_for_domain(tld)
    if not base:
        return {"query": value, **await whois_fallback(".".join(labels[-2:]), tld)}
    # RDAP knows registered domains only: walk from the full name towards the registrable parent (max 4 tries).
    last: FetchError | None = None
    for i in range(0, min(len(labels) - 1, 4)):
        cand = ".".join(labels[i:])
        try:
            doc = await fetch_json(f"{base.rstrip('/')}/domain/{quote(cand, safe='.-_')}", None, RDAP_TIMEOUT)
        except FetchError as exc:
            last = exc
            if exc.not_found:
                continue
            raise HTTPException(status_code=502, detail=f"RDAP lookup failed: {exc}")
        return {"query": value, "registered_domain": cand, "protocol": "rdap", "source": base, **summarise_domain(doc)}
    raise HTTPException(status_code=404, detail=f"{value} is not registered (or the registry returned no record)"
                        if last else "not found")


@router.post("/lookup", dependencies=[Depends(_dep)])
async def whois_lookup(req: WhoisRequest) -> dict:
    """RDAP (IANA bootstrap) for a domain or public IP address; port-43 WHOIS only if the TLD has no RDAP."""
    try:
        parse_target(req.query)
    except TargetError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    key = req.query.strip().lower()
    hit = _cache.get(key)
    if hit is not None:
        return hit
    try:
        async with _gate.slot():
            res = await lookup(req.query)
    except TargetError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    except FetchError as exc:
        raise HTTPException(status_code=502, detail=f"lookup failed: {exc}")
    _cache.set(key, res)
    return res
