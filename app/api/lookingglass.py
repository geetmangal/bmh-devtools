"""Looking glass: ping / traceroute run FROM this server (Noida, AS152523); BGP data from public RIPEstat.

Security model: the command set is fixed (ping, traceroute), run with argv lists via
create_subprocess_exec (never a shell), against a single validated PUBLIC IP literal (a hostname is
resolved first and pinned, every address it resolves to must be public). Hard caps on count, hops and
wall-clock; per-IP token bucket, one run per IP at a time and a global concurrency gate.
Our own routers are never queried: BGP answers come from the RIPEstat data API.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.cache import TTLCache
from app.core.config import (LG_ASN, LG_BURST, LG_LOCATION, LG_PING_COUNT, LG_PING_TIMEOUT, LG_RATE_PER_MIN,
                             LG_TRACE_MAX_HOPS, LG_TRACE_TIMEOUT, MAX_CONCURRENT_LG, RIPESTAT_TIMEOUT, RIPESTAT_URL)
from app.core.httpjson import FetchError, fetch_json
from app.core.ratelimit import Gate, PerIpInflight, TokenBucket, client_ip, limiter
from app.core.target import TargetError, resolve_target
from app.core.validate import is_public_ip

router = APIRouter(prefix="/lg", tags=["looking-glass"])
_gate = Gate(MAX_CONCURRENT_LG, "Looking glass")
_inflight = PerIpInflight(1)
_bucket = TokenBucket(LG_RATE_PER_MIN, LG_BURST)
_dep = limiter(lambda: _bucket, "looking glass", LG_RATE_PER_MIN)
_bgp_cache = TTLCache(300)
MAX_OUTPUT = 16 * 1024
SOURCE = {"asn": LG_ASN, "location": LG_LOCATION, "label": f"from {LG_ASN} {LG_LOCATION.split(',')[0]}"}


class RunRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, examples=["1.1.1.1"])
    tool: Literal["ping", "traceroute"] = "ping"


class BgpRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, examples=["8.8.8.8"])


def build_argv(tool: str, ip: str) -> list[str]:
    """Fixed argv for the two allowed commands. ip is a canonical IP literal from ipaddress (never a
    string the user controls verbatim, never starts with '-')."""
    addr = ipaddress.ip_address(ip)
    fam = "-6" if addr.version == 6 else "-4"
    if tool == "ping":
        return ["ping", fam, "-n", "-c", str(LG_PING_COUNT), "-i", "0.5", "-W", "2", "-w", "10", str(addr)]
    if tool == "traceroute":
        return ["traceroute", fam, "-n", "-q", "1", "-w", "1", "-m", str(LG_TRACE_MAX_HOPS), str(addr)]
    raise ValueError("unsupported tool")


async def _run(argv: list[str], timeout: float) -> tuple[int | None, str, bool]:
    """Execute argv (no shell). Returns (returncode, sanitised output, timed_out). Output capped."""
    exe = shutil.which(argv[0])
    if exe is None:
        raise HTTPException(status_code=503, detail=f"{argv[0]} is not available on this server")
    proc = await asyncio.create_subprocess_exec(
        exe, *argv[1:], stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT, env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    out = bytearray()
    timed_out = False

    async def reader():
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(4096)
            if not chunk:
                break
            if len(out) < MAX_OUTPUT:
                out.extend(chunk[:MAX_OUTPUT - len(out)])

    try:
        await asyncio.wait_for(asyncio.gather(reader(), proc.wait()), timeout)
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
    text = "".join(c if (c == "\n" or 32 <= ord(c) < 127) else "?" for c in out.decode("ascii", "replace"))
    return proc.returncode, redact_internal(text), timed_out


_IP_TOKEN = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)(?![0-9A-Fa-f:.])")


def redact_internal(text: str) -> str:
    """Hide our own internal/private hop addresses (RFC1918, CGNAT, link-local, gateway/host/VR) from output."""
    def sub(m: re.Match) -> str:
        tok = m.group(0)
        try:
            ipaddress.ip_address(tok)
        except ValueError:
            return tok
        return tok if is_public_ip(tok) else "[private]"
    return _IP_TOKEN.sub(sub, text)


_PING_STATS = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?(\d+(?:\.\d+)?)% packet loss")
_PING_RTT = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")
_RTT = re.compile(r"([\d.]+) ms")


def parse_ping(text: str) -> dict:
    m = _PING_STATS.search(text)
    r = _PING_RTT.search(text)
    d: dict = {"sent": None, "received": None, "loss_pct": None, "rtt_ms": None}
    if m:
        d.update(sent=int(m[1]), received=int(m[2]), loss_pct=float(m[3]))
    if r:
        d["rtt_ms"] = {"min": float(r[1]), "avg": float(r[2]), "max": float(r[3]), "mdev": float(r[4])}
    return d


def parse_traceroute(text: str) -> list[dict]:
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d{1,2})\s+(.*)$", line)
        if not m:
            continue
        rest = m[2].strip()
        ip = None
        for tok in rest.split():
            if tok == "[private]":
                ip = "private"
                break
            try:
                ip = str(ipaddress.ip_address(tok))
                break
            except ValueError:
                continue
        rtt = _RTT.search(rest)
        hops.append({"hop": int(m[1]), "ip": ip, "rtt_ms": float(rtt[1]) if rtt else None})
    return hops


@router.post("/run", dependencies=[Depends(_dep)])
async def run(req: RunRequest, request: Request) -> dict:
    """Ping (4 packets) or traceroute (max 30 hops) from this server to a public target."""
    try:
        target, ip, _all = await resolve_target(req.target)
    except TargetError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    argv = build_argv(req.tool, ip)
    timeout = LG_PING_TIMEOUT if req.tool == "ping" else LG_TRACE_TIMEOUT
    async with _inflight.hold(client_ip(request)):
        async with _gate.slot():
            rc, text, timed_out = await _run(argv, timeout)
    res = {"tool": req.tool, "target": target, "resolved_ip": ip, "source": SOURCE, "returncode": rc,
           "timed_out": timed_out, "output": text}
    if req.tool == "ping":
        res["summary"] = parse_ping(text)
        res["reachable"] = bool(res["summary"]["received"])
    else:
        res["hops"] = parse_traceroute(text)
        res["max_hops"] = LG_TRACE_MAX_HOPS
        res["reached"] = any(h["ip"] == ip for h in res["hops"])
    return res


def summarise_bgp(ip: str, overview: dict, lg: dict | None) -> dict:
    d = (overview or {}).get("data") or {}
    asns = [{"asn": f"AS{a.get('asn')}", "holder": a.get("holder")} for a in (d.get("asns") or [])][:10]
    paths: list[dict] = []
    seen: set[str] = set()
    rrcs = ((lg or {}).get("data") or {}).get("rrcs") or []
    for rrc in rrcs:
        for p in rrc.get("peers") or []:
            path = str(p.get("as_path") or "")
            if path and path not in seen and re.fullmatch(r"[0-9 {},]+", path):
                seen.add(path)
                paths.append({"collector": str(rrc.get("rrc", ""))[:16], "location": str(rrc.get("location", ""))[:64],
                              "as_path": path, "prefix": str(p.get("prefix", ""))[:64]})
    paths.sort(key=lambda x: len(x["as_path"].split()))
    return {
        "ip": ip, "prefix": d.get("resource") or d.get("block", {}).get("resource"),
        "announced": bool(d.get("announced")), "origin_asns": asns,
        "block": (d.get("block") or {}).get("desc") or None,
        "paths": paths[:10], "paths_total": len(paths),
        "via_" + LG_ASN.lower(): any(LG_ASN[2:] in p["as_path"].split() for p in paths),
    }


@router.post("/bgp", dependencies=[Depends(_dep)])
async def bgp(req: BgpRequest, request: Request) -> dict:
    """BGP route for the target's prefix from public RIPEstat data (RIPE RIS collectors). Not our routers."""
    try:
        target, ip, _all = await resolve_target(req.target)
    except TargetError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    cached = _bgp_cache.get(ip)
    if cached is None:
        async with _inflight.hold(client_ip(request)):
            async with _gate.slot():
                try:
                    overview = await fetch_json(f"{RIPESTAT_URL}/prefix-overview/data.json",
                                                {"resource": ip}, RIPESTAT_TIMEOUT)
                    prefix = ((overview.get("data") or {}).get("resource")) or ip
                    lg = None
                    try:
                        lg = await fetch_json(f"{RIPESTAT_URL}/looking-glass/data.json",
                                              {"resource": prefix}, RIPESTAT_TIMEOUT)
                    except FetchError:
                        lg = None  # overview alone is still useful
                except FetchError as exc:
                    raise HTTPException(status_code=502, detail=f"RIPEstat lookup failed: {exc}")
        cached = summarise_bgp(ip, overview, lg)
        _bgp_cache.set(ip, cached)
    return {"target": target, "source": {"name": "RIPEstat (RIPE NCC RIS route collectors)", "url": "https://stat.ripe.net/",
                                          "note": f"Public BGP data, not a query to {LG_ASN} routers."},
            **cached}
