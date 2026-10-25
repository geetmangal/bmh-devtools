"""IPv4/IPv6 subnet calculator backed by python ipaddress."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.config import MAX_SPLIT_SUBNETS
from app.core.ratelimit import rate_limit

router = APIRouter(prefix="/subnet", tags=["subnet"])


class CalcRequest(BaseModel):
    cidr: str = Field(..., min_length=1, max_length=64, examples=["10.0.0.0/22"])


class SplitRequest(BaseModel):
    cidr: str = Field(..., min_length=1, max_length=64, examples=["10.0.0.0/22"])
    new_prefix: int = Field(..., ge=0, le=128, examples=[24])


class SummariseRequest(BaseModel):
    cidrs: list[str] = Field(..., min_length=1, max_length=256)


def _parse(cidr: str):
    try:
        return ipaddress.ip_interface(cidr.strip())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid CIDR: {exc}")


def _class(ip: ipaddress.IPv4Address) -> str:
    first = int(ip) >> 24
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (reserved)"


def _reverse_zone(net) -> str:
    if net.version == 4:
        octets = str(net.network_address).split(".")
        keep = max(1, net.prefixlen // 8)
        return ".".join(reversed(octets[:keep])) + ".in-addr.arpa"
    nibbles = net.network_address.exploded.replace(":", "")
    keep = max(1, net.prefixlen // 4)
    return ".".join(reversed(nibbles[:keep])) + ".ip6.arpa"


def calc(cidr: str) -> dict:
    iface = _parse(cidr)
    net = iface.network
    ip = iface.ip
    v4 = net.version == 4
    total = net.num_addresses
    if v4:
        if net.prefixlen >= 31:
            usable = total
            first, last = net.network_address, net.broadcast_address
        else:
            usable = total - 2
            first, last = net.network_address + 1, net.broadcast_address - 1
    else:
        if net.prefixlen >= 127:
            usable = total
            first = net.network_address
        else:
            usable = total - 1  # subnet-router anycast address reserved
            first = net.network_address + 1
        last = net.broadcast_address
    out = {
        "input": cidr.strip(),
        "version": net.version,
        "ip": str(ip),
        "network": str(net.network_address),
        "cidr": str(net),
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "broadcast": str(net.broadcast_address) if v4 else None,
        "first_usable": str(first),
        "last_usable": str(last),
        "total_addresses": total if v4 else str(total),
        "usable_hosts": usable if v4 else str(usable),
        "is_private": net.is_private,
        "is_global": net.is_global,
        "is_loopback": net.is_loopback,
        "is_link_local": net.is_link_local,
        "is_multicast": net.is_multicast,
        "reverse_dns_zone": _reverse_zone(net),
        "ip_binary": ".".join(f"{int(o):08b}" for o in str(ip).split(".")) if v4
        else ":".join(f"{int(h, 16):016b}" for h in ip.exploded.split(":")),
        "netmask_binary": ".".join(f"{int(o):08b}" for o in str(net.netmask).split(".")) if v4 else None,
        "ip_hex": f"0x{int(ip):08x}" if v4 else f"0x{int(ip):032x}",
        "ip_integer": int(ip) if v4 else str(int(ip)),
    }
    if v4:
        out["class"] = _class(ip)
    else:
        out["compressed"] = ip.compressed
        out["exploded"] = ip.exploded
    return out


@router.post("/calc", dependencies=[Depends(rate_limit)])
async def subnet_calc(req: CalcRequest) -> dict:
    """Full CIDR breakdown for an IPv4 or IPv6 address/prefix."""
    return calc(req.cidr)


@router.post("/split", dependencies=[Depends(rate_limit)])
async def subnet_split(req: SplitRequest) -> dict:
    """Split a prefix into equal subnets of new_prefix length (max 1024)."""
    net = _parse(req.cidr).network
    if req.new_prefix <= net.prefixlen:
        raise HTTPException(status_code=422, detail="new_prefix must be longer than the current prefix")
    if req.new_prefix > net.max_prefixlen:
        raise HTTPException(status_code=422, detail="new_prefix too long for this address family")
    count = 2 ** (req.new_prefix - net.prefixlen)
    if count > MAX_SPLIT_SUBNETS:
        raise HTTPException(status_code=422, detail=f"would produce {count} subnets; cap is {MAX_SPLIT_SUBNETS}")
    subs = list(net.subnets(new_prefix=req.new_prefix))
    return {"cidr": str(net), "new_prefix": req.new_prefix, "count": len(subs),
            "subnets": [{"cidr": str(s), "first": str(s.network_address), "last": str(s.broadcast_address),
                         "addresses": str(s.num_addresses)} for s in subs]}


@router.post("/summarise", dependencies=[Depends(rate_limit)])
async def subnet_summarise(req: SummariseRequest) -> dict:
    """Collapse / supernet a list of CIDRs."""
    nets = []
    for c in req.cidrs:
        try:
            nets.append(ipaddress.ip_network(c.strip(), strict=False))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"invalid CIDR {c!r}: {exc}")
    if len({n.version for n in nets}) > 1:
        raise HTTPException(status_code=422, detail="mix of IPv4 and IPv6 is not supported")
    collapsed = list(ipaddress.collapse_addresses(nets))
    lo = min(n.network_address for n in nets)
    hi = max(n.broadcast_address for n in nets)
    exact = list(ipaddress.summarize_address_range(lo, hi))
    cover = nets[0]
    while cover.prefixlen > 0 and not all(n.subnet_of(cover) for n in nets):
        cover = cover.supernet()
    return {"input": [str(n) for n in nets], "collapsed": [str(n) for n in collapsed],
            "exact_range_summary": [str(n) for n in exact], "single_supernet": str(cover)}
