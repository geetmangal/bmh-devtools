"""Resolve and validate a user-supplied probe target (IP literal or hostname) to PUBLIC addresses only."""
from __future__ import annotations

import asyncio
import ipaddress
import socket

from app.core.config import RDAP_TIMEOUT
from app.core.validate import ValidationError, is_ip_literal, is_public_ip, normalise_hostname

_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet", ".corp")


class TargetError(ValueError):
    """Target refused or unresolvable. status is the HTTP status to return (422 refused, 400 unresolvable)."""

    def __init__(self, msg: str, status: int = 422) -> None:
        super().__init__(msg)
        self.status = status


def parse_target(raw: str) -> tuple[str, bool]:
    """Return (value, is_ip). IP literals must be public; hostnames must look like real DNS names.
    Only [a-z0-9.-_] hostnames or canonical IP text can come out, so the value can never be a
    command-line option, contain whitespace or shell metacharacters."""
    if not isinstance(raw, str):
        raise TargetError("target must be a string")
    raw = raw.strip()
    if not raw or len(raw) > 253 or raw.startswith("-"):
        raise TargetError("invalid target")
    if is_ip_literal(raw):
        ip = raw.strip("[]")
        if "%" in ip:
            raise TargetError("scoped addresses are not allowed")
        if not is_public_ip(ip):
            raise TargetError(f"{ip} is a private, internal, link-local, multicast or reserved address; "
                              "only public targets are allowed")
        return str(ipaddress.ip_address(ip)), True
    try:
        host = normalise_hostname(raw)
    except ValidationError as exc:
        raise TargetError(str(exc)) from exc
    if host.split(".")[-1].isdigit() or "." not in host or host == "localhost" or host.endswith(_LOCAL_SUFFIXES):
        raise TargetError("local, single-label or malformed hostnames are not allowed")
    return host, False


async def resolve_public(host: str, timeout: float = RDAP_TIMEOUT) -> list[str]:
    """getaddrinfo host; if ANY answer is non-public the whole target is refused. IPv4 first."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout)
    except (socket.gaierror, asyncio.TimeoutError, UnicodeError) as exc:
        raise TargetError(f"could not resolve {host}", 400) from exc
    ips: list[str] = []
    for _f, *_r, sa in infos:
        if sa[0] not in ips:
            ips.append(sa[0])
    if not ips:
        raise TargetError(f"no addresses for {host}", 400)
    for ip in ips:
        if not is_public_ip(ip):
            raise TargetError(f"{host} resolves to a non-public address ({ip}); refusing", 422)
    ips.sort(key=lambda s: ":" in s)
    return ips


async def resolve_target(raw: str) -> tuple[str, str, list[str]]:
    """Return (display value, chosen public IP, all public IPs)."""
    value, is_ip = parse_target(raw)
    if is_ip:
        return value, value, [value]
    ips = await resolve_public(value)
    return value, ips[0], ips
