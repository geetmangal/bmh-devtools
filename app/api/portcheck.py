"""Open port checker. Connects ONLY to the visitor's own IP address, taken from the request
(client_ip: X-Real-IP set by nginx from the Cloudflare-verified address). There is deliberately no
host/target/ip field in the request model: unknown JSON fields and query parameters are ignored."""
from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import COMMON_PORTS, MAX_CONCURRENT_NET, PORT_RATE_PER_MIN, PORT_TIMEOUT
from app.core.turnstile import require_pass
from app.core.ratelimit import Gate, TokenBucket, client_ip, limiter
from app.core.validate import is_ip_literal, is_public_ip

router = APIRouter(prefix="/ports", tags=["port-checker"])
_gate = Gate(MAX_CONCURRENT_NET, "Port")
_bucket = TokenBucket(PORT_RATE_PER_MIN, 4)
_dep = limiter(lambda: _bucket, "port check", PORT_RATE_PER_MIN)

SERVICES = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            465: "SMTPS", 587: "SMTP submission", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 8080: "HTTP alt", 8443: "HTTPS alt"}


class PortRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")  # target/host/ip fields are silently dropped, never used
    port: int | None = Field(None, ge=1, le=65535, examples=[443])
    common: bool = False


def visitor_ip(request: Request) -> str:
    ip = client_ip(request).strip().strip("[]")
    if not is_ip_literal(ip) or not is_public_ip(ip):
        raise HTTPException(status_code=422, detail="Your address is not a public IP (private, loopback or "
                            "behind a proxy we cannot see through), so it cannot be checked from the internet.")
    return ip


async def probe(ip: str, port: int) -> dict:
    t0 = time.perf_counter()
    res = {"port": port, "service": SERVICES.get(port), "state": "filtered", "ms": None}
    try:
        _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), PORT_TIMEOUT)
        res.update(state="open", ms=round((time.perf_counter() - t0) * 1000))
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), 1)
        except Exception:
            pass
    except asyncio.TimeoutError:
        res["state"] = "filtered"  # no answer in 3 s: firewall drop or host down
    except ConnectionRefusedError:
        res.update(state="closed", ms=round((time.perf_counter() - t0) * 1000))
    except OSError:
        res["state"] = "error"
    return res


@router.post("/check", dependencies=[Depends(require_pass), Depends(_dep)])
async def check(req: PortRequest, request: Request) -> dict:
    """Check one TCP port (1-65535) or the common-port set on the caller's own IP only."""
    if req.port is None and not req.common:
        raise HTTPException(status_code=422, detail="Give a port (1-65535) or common=true")
    ip = visitor_ip(request)
    ports = list(COMMON_PORTS) if req.common else [req.port]
    async with _gate.slot():
        results = await asyncio.gather(*(probe(ip, p) for p in ports))
    return {"ip": ip, "timeout_s": PORT_TIMEOUT, "results": list(results),
            "note": "Checked from the BookMyHost Noida server to your own public IP only."}


@router.get("/myip")
async def myip(request: Request) -> dict:
    """The address the checker will test (shown on the page before running)."""
    ip = client_ip(request).strip()
    return {"ip": ip, "public": is_ip_literal(ip) and is_public_ip(ip)}
