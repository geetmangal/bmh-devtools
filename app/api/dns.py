"""DNS propagation checker: query many public resolvers concurrently."""
from __future__ import annotations

import asyncio
import time
from typing import Literal

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import dns.rcode
import dns.rdatatype
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.config import DNS_TIMEOUT, MAX_CONCURRENT_DNS
from app.core.ratelimit import Gate, rate_limit
from app.core.validate import ValidationError, is_public_ip, normalise_hostname, validate_ptr_target

router = APIRouter(prefix="/dns", tags=["dns"])
_gate = Gate(MAX_CONCURRENT_DNS, "DNS")

RecordType = Literal["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR"]

# label, country code, IP. All are public recursive resolvers.
# Anycast resolvers answer from the PoP nearest to this server; the region label
# describes the operator / the PoP we expect when the checker runs from India.
RESOLVERS: list[tuple[str, str, str]] = [
    ("Google", "US", "8.8.8.8"),
    ("Cloudflare", "US", "1.1.1.1"),
    ("Quad9", "CH", "9.9.9.9"),
    ("OpenDNS", "US", "208.67.222.222"),
    ("Level3", "US", "4.2.2.2"),
    ("Comodo Secure", "US", "8.26.56.26"),
    ("CleanBrowsing", "US", "185.228.168.9"),
    ("AdGuard", "CY", "94.140.14.14"),
    ("Yandex", "RU", "77.88.8.8"),
    ("Hurricane Electric", "US", "74.82.42.42"),
    ("Google (India anycast)", "IN", "8.8.4.4"),
    ("Cloudflare (India anycast)", "IN", "1.0.0.1"),
    ("DNS.SB (Singapore)", "SG", "185.222.222.222"),
    ("DNS.WATCH (Germany)", "DE", "84.200.69.80"),
    ("CloudNS (Australia)", "AU", "45.90.28.0"),
    ("Quad9 secondary (Brazil anycast)", "BR", "149.112.112.112"),
    ("DNS.SB secondary (Japan/Asia anycast)", "JP", "45.11.45.11"),
    ("Control D (USA)", "US", "76.76.2.0"),
]


class PropagationRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=253, examples=["bookmyhost.com"])
    type: RecordType = "A"


def _fmt(rr, rtype: str) -> str:
    return rr.to_text().rstrip(".") if rtype in ("CNAME", "NS", "PTR") else rr.to_text()


async def _query(label: str, country: str, ip: str, qname: str, rtype: str) -> dict:
    q = dns.message.make_query(qname, rtype)
    t0 = time.perf_counter()
    result = {"label": label, "country": country, "ip": ip, "answers": [], "ttl": None,
              "rtt_ms": None, "status": "timeout"}
    try:
        resp = await asyncio.wait_for(dns.asyncquery.udp(q, ip, timeout=DNS_TIMEOUT), DNS_TIMEOUT + 0.2)
        result["rtt_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        rc = resp.rcode()
        if rc == dns.rcode.NXDOMAIN:
            result["status"] = "nxdomain"
        elif rc == dns.rcode.SERVFAIL:
            result["status"] = "servfail"
        elif rc == dns.rcode.NOERROR:
            result["status"] = "ok"
            want = dns.rdatatype.from_text(rtype)
            for rrset in resp.answer:
                if rrset.rdtype == want:
                    result["answers"].extend(_fmt(rr, rtype) for rr in rrset)
                    result["ttl"] = rrset.ttl
            result["answers"].sort()
        else:
            result["status"] = dns.rcode.to_text(rc).lower()
    except (asyncio.TimeoutError, dns.exception.Timeout):
        result["status"] = "timeout"
    except Exception as exc:  # network error, refused etc.
        result["status"] = "error"
        result["error"] = type(exc).__name__
    return result


async def _authoritative(qname: str, rtype: str) -> dict:
    """Find the zone NS set (walking up labels) and ask one authoritative server directly."""
    res = dns.asyncresolver.Resolver(configure=False)
    res.nameservers = ["1.1.1.1", "8.8.8.8"]
    res.lifetime = DNS_TIMEOUT * 2
    labels = qname.split(".")
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        try:
            ns_ans = await res.resolve(zone, "NS")
        except Exception:
            continue
        ns_names = sorted(rr.target.to_text().rstrip(".") for rr in ns_ans)
        for ns in ns_names:
            try:
                ns_ip = (await res.resolve(ns, "A"))[0].to_text()
            except Exception:
                continue
            if not is_public_ip(ns_ip):  # SSRF: a zone can delegate to an internal address
                continue
            r = await _query(f"authoritative: {ns}", "", ns_ip, qname, rtype)
            r.update({"zone": zone, "nameservers": ns_names})
            return r
        break
    return {"status": "unknown", "answers": [], "zone": None, "nameservers": []}


@router.post("/propagation", dependencies=[Depends(rate_limit)])
async def propagation(req: PropagationRequest) -> dict:
    """Query 18 public resolvers worldwide concurrently and compare with the authoritative answer."""
    try:
        qname = validate_ptr_target(req.name) if req.type == "PTR" else normalise_hostname(req.name)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    async with _gate.slot():
        tasks = [_query(l, c, ip, qname, req.type) for l, c, ip in RESOLVERS]
        results, auth = await asyncio.gather(asyncio.gather(*tasks), _authoritative(qname, req.type))
    auth_set = set(auth.get("answers") or [])
    ok = [r for r in results if r["status"] == "ok"]
    if auth_set:
        propagated = sum(1 for r in ok if set(r["answers"]) == auth_set)
    else:
        propagated = sum(1 for r in ok if r["answers"])
    for r in results:
        r["matches_authoritative"] = bool(auth_set) and set(r["answers"]) == auth_set
    return {
        "name": qname, "type": req.type,
        "queried_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "authoritative": auth,
        "resolvers": results,
        "summary": {"propagated": propagated, "total": len(results),
                    "text": f"propagated {propagated}/{len(results)}"},
    }
