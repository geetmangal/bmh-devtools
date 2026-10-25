"""Strict input validation shared by all tools."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from app.core.config import ALLOWED_PORTS, BLOCKED_NETS

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
MAX_NAME_LEN = 253
_BLOCKED = [ipaddress.ip_network(n, strict=False) for n in BLOCKED_NETS]


class ValidationError(ValueError):
    pass


def normalise_hostname(name: str) -> str:
    """Return a lower-case, IDNA-encoded (ASCII) hostname or raise ValidationError."""
    if not isinstance(name, str):
        raise ValidationError("hostname must be a string")
    name = name.strip().rstrip(".").lower()
    if not name or len(name) > MAX_NAME_LEN:
        raise ValidationError("hostname is empty or too long")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:
        raise ValidationError("hostname is not valid IDNA") from exc
    labels = ascii_name.split(".")
    for label in labels:
        if not _LABEL.match(label):
            raise ValidationError(f"invalid hostname label: {label!r}")
    return ascii_name


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    """True only for globally routable unicast addresses that are not on the block list
    (rejects loopback, RFC1918, link-local incl. 169.254.169.254, CGNAT, multicast, reserved,
    ULA, NAT64/6to4/Teredo wrappers, IPv4-mapped forms, and the hosting network's gateway,
    virtual router and own addresses)."""
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None or ip.teredo is not None:
            return False
    for net in _BLOCKED:
        if ip.version == net.version and ip in net:
            return False
    return bool(ip.is_global) and not ip.is_multicast and not ip.is_reserved \
        and not ip.is_loopback and not ip.is_link_local and not ip.is_private and not ip.is_unspecified


def assert_public_ip(value: str) -> None:
    if not is_public_ip(value):
        raise ValidationError(f"address {value} is private, internal, link-local or reserved")


def validate_ptr_target(value: str) -> str:
    """For PTR queries accept an IP (must be public) or an in-addr.arpa/ip6.arpa name."""
    value = value.strip()
    if is_ip_literal(value):
        assert_public_ip(value)
        return ipaddress.ip_address(value).reverse_pointer
    name = normalise_hostname(value)
    if not (name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa")):
        raise ValidationError("PTR target must be an IP address or a .arpa name")
    return name


def validate_url(url: str) -> tuple[str, str, int, str]:
    """Validate a URL for the HTTP checker. Returns (scheme, host, port, path+query)."""
    if not isinstance(url, str):
        raise ValidationError("url must be a string")
    url = url.strip()
    if len(url) > 2048:
        raise ValidationError("url too long")
    if any(c in url for c in "\r\n\t\x00 "):
        raise ValidationError("url contains whitespace or control characters")
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValidationError("only http and https URLs are allowed")
    if parts.username or parts.password:
        raise ValidationError("credentials in URL are not allowed")
    if not parts.hostname:
        raise ValidationError("url has no host")
    host = parts.hostname
    if is_ip_literal(host):
        assert_public_ip(host)
        host = str(ipaddress.ip_address(host))
    else:
        host = normalise_hostname(host)
        if host.split(".")[-1].isdigit() or re.fullmatch(r"0x[0-9a-f]+", host):
            raise ValidationError("malformed IP address literal")
        if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local") \
                or host.endswith(".internal") or host.endswith(".home.arpa") or "." not in host:
            raise ValidationError("local hostnames are not allowed")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValidationError("invalid port") from exc
    if port not in ALLOWED_PORTS:
        raise ValidationError(f"port {port} not allowed (use 80, 443, 8080 or 8443)")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme, host, port, path
