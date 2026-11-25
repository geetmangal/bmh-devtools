"""Cloudflare Turnstile verification and the signed "tool pass".

A visitor solves one Turnstile challenge; /tools/api/v1/pass exchanges the token for a short-lived
HMAC-signed pass bound to the client network (IPv4 /24, IPv6 /48) and the User-Agent hash. Heavy tools
then require the pass in the X-Tools-Pass header, so users see one challenge per session, not per call.

Turnstile is enabled only when TURNSTILE_SITEKEY, TURNSTILE_SECRET and TOOLS_PASS_SECRET are all set.
Otherwise require_pass is a no-op (a warning is logged once at startup).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import time

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse

from app.core import config
from app.core.ratelimit import client_ip

log = logging.getLogger("bmh_tools")


class PassRequired(Exception):
    """Raised by require_pass; main.py turns it into the 403 {"error": "pass_required"} body."""


def enabled() -> bool:
    return bool(config.TURNSTILE_SITEKEY and config.TURNSTILE_SECRET and config.TOOLS_PASS_SECRET)


def warn_if_disabled() -> None:
    if not enabled():
        log.warning("Turnstile disabled: set TURNSTILE_SITEKEY, TURNSTILE_SECRET and TOOLS_PASS_SECRET "
                    "to protect heavy tools")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def network_of(ip: str) -> str:
    """IPv4 -> its /24, IPv6 -> its /48 (so a client moving inside its network keeps the pass)."""
    try:
        addr = ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError:
        return "invalid"
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    plen = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))


def ua_hash(ua: str) -> str:
    return hashlib.sha256((ua or "").encode()).hexdigest()[:16]


def _sign(payload: bytes) -> bytes:
    return hmac.new(config.TOOLS_PASS_SECRET.encode(), payload, hashlib.sha256).digest()


def issue_pass(ip: str, ua: str, now: float | None = None) -> str:
    payload = json.dumps({"exp": int((now if now is not None else time.time()) + config.PASS_TTL),
                          "net": network_of(ip), "ua": ua_hash(ua)}, separators=(",", ":")).encode()
    return _b64(payload) + "." + _b64(_sign(payload))


def check_pass(blob: str | None, ip: str, ua: str, now: float | None = None) -> bool:
    if not blob or not config.TOOLS_PASS_SECRET or blob.count(".") != 1 or len(blob) > 512:
        return False
    try:
        p_b64, s_b64 = blob.split(".")
        payload, sig = _unb64(p_b64), _unb64(s_b64)
        if not hmac.compare_digest(sig, _sign(payload)):
            return False
        data = json.loads(payload)
        if not isinstance(data, dict):
            return False
        if int(data.get("exp", 0)) < (now if now is not None else time.time()):
            return False
        return (hmac.compare_digest(str(data.get("net", "")).encode(), network_of(ip).encode())
                and hmac.compare_digest(str(data.get("ua", "")).encode(), ua_hash(ua).encode()))
    except Exception:
        return False


async def verify(token: str, ip: str) -> bool:
    """siteverify with a 5 s timeout. Raises httpx.HTTPError when Cloudflare is unreachable
    (the caller turns that into 503: heavy tools fail closed)."""
    async with httpx.AsyncClient(timeout=5.0) as c:
        r = await c.post(config.TURNSTILE_VERIFY_URL,
                         data={"secret": config.TURNSTILE_SECRET, "response": token, "remoteip": ip})
        r.raise_for_status()
        return bool(r.json().get("success"))


def is_bypass_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError:
        return False
    for c in config.TURNSTILE_BYPASS_IPS:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def pass_required_response() -> JSONResponse:
    return JSONResponse({"error": "pass_required"}, status_code=403, headers={"Cache-Control": "no-store"})


async def require_pass(request: Request) -> None:
    """FastAPI dependency for heavy endpoints: 403 {"error": "pass_required"} without a valid pass."""
    if not enabled():
        return
    ip = client_ip(request)
    if is_bypass_ip(ip):
        return
    if not check_pass(request.headers.get("x-tools-pass"), ip, request.headers.get("user-agent", "")):
        raise PassRequired()


class TurnstileRequired(Exception):
    """Raised by require_fresh_token; main.py turns it into the 403 {"error": "turnstile_required"} body."""

    def __init__(self, message: str = "Please complete the human check and run the test again.", status: int = 403,
                 code: str = "turnstile_required") -> None:
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def turnstile_required_response(exc: TurnstileRequired) -> JSONResponse:
    return JSONResponse({"error": exc.code, "message": exc.message}, status_code=exc.status,
                        headers={"Cache-Control": "no-store"})


async def require_fresh_token(request: Request) -> None:
    """Strict mode for the most abusable tools: a FRESH single-use Turnstile token (X-Turnstile-Token) is
    verified per request, on top of the session pass. Missing/invalid/reused -> 403 turnstile_required.
    Cloudflare unreachable -> fail closed (503 turnstile_unavailable). No-op when Turnstile is off or for bypass IPs."""
    if not enabled():
        return
    ip = client_ip(request)
    if is_bypass_ip(ip):
        return
    token = (request.headers.get("x-turnstile-token") or "").strip()
    if not token or len(token) > 4096:
        raise TurnstileRequired()
    try:
        ok = await verify(token, ip)
    except (httpx.HTTPError, ValueError):
        raise TurnstileRequired("Could not reach the verification service. Please try again in a minute.", 503,
                                "turnstile_unavailable")
    if not ok:
        raise TurnstileRequired("The human check expired or was already used. Please solve it again and re-run the test.")
