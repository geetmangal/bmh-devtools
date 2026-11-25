"""Reverse-DNS view of a prefix: delegation (NS + DS) and a bounded PTR sweep with FCrDNS marks.

Everything goes through an injectable resolver (``app.core.mailcheck.resolver``: the unbound sidecar in
production, ``FakeResolver`` in tests). IPv4 gets the sweep (one /24 slice per request); IPv6 only the delegation.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import time

from app.core.mailcheck.resolver import DnsResolver, Resolver

BUDGET = 8.0
CONCURRENCY = 32
MAX_PTR_LEN = 253
V6_NOTE = "IPv6: only the delegation is shown"
_SEP = r"[-._x]"


def make_resolver() -> Resolver:
    """Resolver used by the API (honours BMH_TOOLS_MAILCHECK_RESOLVERS); tests monkeypatch this."""
    return DnsResolver(timeout=1.5, lifetime=3.0)


# --- slicing ----------------------------------------------------------------------------------------
def slices(net: ipaddress.IPv4Network) -> list[ipaddress.IPv4Network]:
    """The /24 slices of an IPv4 prefix (a prefix longer than /24 is one slice: its covering /24)."""
    if net.prefixlen >= 24:
        return [ipaddress.ip_network(f"{net.network_address}/24", strict=False)]
    return list(net.subnets(new_prefix=24))


def block_count(net: ipaddress.IPv4Network) -> int:
    return 1 if net.prefixlen >= 24 else 1 << (24 - net.prefixlen)


def block_net(net: ipaddress.IPv4Network, block: int) -> ipaddress.IPv4Network:
    if net.prefixlen >= 24:
        return ipaddress.ip_network(f"{net.network_address}/24", strict=False)
    return ipaddress.ip_network((int(net.network_address) + block * 256, 24))


def ips_of_block(net: ipaddress.IPv4Network, base: ipaddress.IPv4Network) -> list[str]:
    """Addresses to scan: the whole /24 slice, but only what lies inside the prefix when it is smaller than a /24."""
    if net.prefixlen >= 24:
        return [str(a) for a in net]
    return [str(a) for a in base]


# --- heuristics -------------------------------------------------------------------------------------
def looks_auto(ptr: str, ip: str) -> bool:
    """True when the PTR just embeds the IP (160-22-108-1.isp.net, 1.108.22.160.static..., a0166c01.x)."""
    a = ipaddress.ip_address(ip)
    if a.version != 4:
        return a.exploded.replace(":", "") in ptr.replace("-", "").replace(".", "").lower()
    octets = ip.split(".")
    p = ptr.lower()
    for seq in (octets, octets[::-1]):
        if re.search(r"(?<!\d)" + _SEP.join(seq) + r"(?!\d)", p):
            return True
    labels = p.split(".")
    hexip = f"{int(a):08x}"
    for lab in labels:
        if hexip in lab or (re.fullmatch(r"\d{8,10}", lab) and int(lab) == int(a)):
            return True
        if re.fullmatch(r"(?:ip|host|dhcp|dyn|static|cust|client|pool|adsl|cpe)?[-_]?\d{1,3}(?:[-_]\d{1,3}){3}", lab):
            return True
    return False


# --- delegation -------------------------------------------------------------------------------------
def v4_zone(net: ipaddress.IPv4Network, upto: int) -> str:
    """in-addr.arpa zone covering the first ``upto`` octets of the network address."""
    octets = str(net.network_address).split(".")[:upto]
    return ".".join(reversed(octets)) + ".in-addr.arpa"


def v6_zone(net: ipaddress.IPv6Network, nibbles: int) -> str:
    rp = net.network_address.reverse_pointer.split(".")[:-2]   # 32 nibbles, least significant first
    return ".".join(rp[32 - nibbles:]) + ".ip6.arpa"


async def delegation(resolver: Resolver, zones: list[str]) -> list[dict]:
    """First zone of ``zones`` (most specific first) that has NS records, with its DS state."""
    for zone in zones:
        ns = await resolver.query(zone, "NS")
        if ns.ok:
            ds = await resolver.query(zone, "DS")
            ds_state = True if ds.ok else (False if ds.status in ("noanswer", "nxdomain") else None)
            names = sorted(set(ns.records))[:10]
            return [{"zone": zone, "ns": names, "ds": ds_state, "ns_problems": await ns_problems(resolver, names)}]
    return []


async def ns_problems(resolver: Resolver, names: list[str]) -> list[dict]:
    """Name servers outside resolvers cannot reach: a bare host name such as ``win-8h6jmqbvgp2`` (``not_fqdn``) or a
    name with neither an A nor an AAAA record (``no_address``). Timeouts and SERVFAILs are not flagged (unknown)."""
    async def one(name: str) -> dict | None:
        host = name.strip().rstrip(".")
        if "." not in host:
            return {"ns": name, "problem": "not_fqdn"}
        a, aaaa = await asyncio.gather(resolver.query(host, "A"), resolver.query(host, "AAAA"))
        if a.ok or aaaa.ok:
            return None
        if all(r.status in ("noanswer", "nxdomain") for r in (a, aaaa)):
            return {"ns": name, "problem": "no_address"}
        return None
    return [r for r in await asyncio.gather(*(one(n) for n in names)) if r]


# --- PTR sweep --------------------------------------------------------------------------------------
async def sweep(ips: list[str], resolver: Resolver, budget: float = BUDGET, concurrency: int = CONCURRENCY) -> dict:
    rows = {ip: {"ip": ip, "ptr": None, "fcrdns": None, "auto": False} for ip in ips}
    done: set[str] = set()
    sem = asyncio.Semaphore(concurrency)

    async def one(ip: str) -> None:
        async with sem:
            rev = ipaddress.ip_address(ip).reverse_pointer
            res = await resolver.query(rev, "PTR")
            if res.ok:
                names = [r[:MAX_PTR_LEN] for r in res.records[:3]]
                row = rows[ip]
                row["ptr"] = names[0]
                row["auto"] = looks_auto(names[0], ip)
                confirmed: bool | None = None
                for name in names[:2]:
                    fwd = await resolver.query(name, "A")
                    if fwd.ok:
                        if ip in fwd.records:
                            confirmed = True
                            break
                        confirmed = False
                    elif fwd.status in ("nxdomain", "noanswer"):
                        confirmed = False if confirmed is None else confirmed
                row["fcrdns"] = confirmed
            done.add(ip)

    tasks = [asyncio.ensure_future(one(ip)) for ip in ips]
    partial = False
    try:
        if tasks:
            _d, pending = await asyncio.wait(tasks, timeout=budget)
            partial = bool(pending)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    out = [rows[ip] for ip in ips]
    stats = {"scanned": len(done), "with_ptr": sum(1 for r in out if r["ptr"]),
             "fcrdns_ok": sum(1 for r in out if r["fcrdns"] is True),
             "auto_generated": sum(1 for r in out if r["auto"])}
    return {"rows": out, "stats": stats, "partial": partial}


# --- report -----------------------------------------------------------------------------------------
async def report(prefix: str, block: int = 0, resolver: Resolver | None = None, budget: float = BUDGET) -> dict:
    """Body of POST /prefix-rdns. Raises ValueError for a bad block index."""
    resolver = resolver or make_resolver()
    net = ipaddress.ip_network(prefix, strict=False)
    t0 = time.monotonic()
    if net.version == 6:
        n = max(net.prefixlen // 4, 1)
        zones = [v6_zone(net, k) for k in range(n, max(n - 4, 0), -1)]
        deleg = await delegation(resolver, zones)
        return {"prefix": str(net), "family": 6, "block": 0, "blocks": 1, "base": str(net), "delegations": deleg,
                "rows": [], "stats": {"scanned": 0, "with_ptr": 0, "fcrdns_ok": 0, "auto_generated": 0},
                "partial": False, "note": V6_NOTE, "elapsed_ms": round((time.monotonic() - t0) * 1000)}
    blocks = block_count(net)
    if not 0 <= block < blocks:
        raise ValueError(f"block must be between 0 and {blocks - 1}")
    base = block_net(net, block)
    deleg = await delegation(resolver, [v4_zone(base, 3), v4_zone(base, 2), v4_zone(base, 1)])
    ips = ips_of_block(net, base)
    sw = await sweep(ips, resolver, budget)
    note = None
    if net.prefixlen > 24:
        note = f"The prefix is smaller than a /24: only its {len(ips)} address(es) were scanned."
    elif sw["partial"]:
        note = "The scan hit its time limit; unfinished addresses are shown without a PTR."
    return {"prefix": str(net), "family": 4, "block": block, "blocks": blocks, "base": str(base), "delegations": deleg,
            "rows": sw["rows"], "stats": sw["stats"], "partial": sw["partial"], "note": note,
            "elapsed_ms": round((time.monotonic() - t0) * 1000)}
