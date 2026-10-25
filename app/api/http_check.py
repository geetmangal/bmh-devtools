"""TTFB + SSL checker with real per-phase timing over raw asyncio sockets."""
from __future__ import annotations

import asyncio
import datetime as dt
import socket
import ssl
import time
from urllib.parse import urljoin

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.config import HTTP_TIMEOUT, MAX_CONCURRENT_HTTP, MAX_REDIRECTS, MAX_RESPONSE_BYTES
from app.core.ratelimit import Gate, rate_limit
from app.core.validate import ValidationError, is_ip_literal, is_public_ip, validate_url

router = APIRouter(prefix="/http", tags=["http"])

USER_AGENT = "BookMyHost-DevTools/1.0 (+https://bookmyhost.com/tools/ttfb-ssl-checker)"
SAMPLES = 3
_gate = Gate(MAX_CONCURRENT_HTTP, "HTTP")


class CheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, examples=["https://bookmyhost.com"])


class CheckError(Exception):
    pass


async def _resolve(host: str) -> tuple[str, float]:
    """Resolve host -> public IP. Returns (ip, dns_ms). Rejects private targets (SSRF guard):
    if ANY address the name resolves to is non-public or blocked, the whole check is refused.
    Callers connect to the returned IP literal (never re-resolve the name), so a DNS rebinding
    answer cannot swap in an internal address between this check and the connect."""
    if is_ip_literal(host):
        if not is_public_ip(host):
            raise CheckError(f"{host} is not a public address; refusing to connect")
        return host, 0.0
    loop = asyncio.get_running_loop()
    t0 = time.perf_counter()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), HTTP_TIMEOUT)
    except (socket.gaierror, asyncio.TimeoutError) as exc:
        raise CheckError(f"DNS lookup failed for {host}: {exc}") from exc
    dns_ms = (time.perf_counter() - t0) * 1000
    ips = []
    for fam, *_rest, sa in infos:
        ip = sa[0]
        if ip not in ips:
            ips.append(ip)
    # prefer IPv4 for a predictable path; fall back to IPv6
    ips.sort(key=lambda s: ":" in s)
    for ip in ips:
        if not is_public_ip(ip):
            raise CheckError(f"{host} resolves to a non-public address ({ip}); refusing to connect")
    if not ips:
        raise CheckError(f"no addresses for {host}")
    return ips[0], dns_ms


def _ssl_context(verify: bool, alpn: list[str]) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(alpn)
    except NotImplementedError:
        pass
    return ctx


def _parse_headers(raw: bytes) -> tuple[str, int, str, dict[str, str]]:
    head, _, _ = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise CheckError("malformed HTTP status line")
    version = parts[0][5:]
    status = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if k:
            headers[k.strip().lower()] = v.strip()
    return version, status, reason, headers


async def _fetch_once(scheme: str, host: str, port: int, path: str, verify: bool = True,
                      pinned: tuple[str, float] | None = None) -> dict:
    """One GET with phase timings. Returns dict of timings, status, headers, body size, ssl object info.
    `pinned` = (ip, dns_ms) from _resolve(); the socket always goes to that validated IP literal."""
    phases: dict[str, float] = {}
    ip, dns_ms = pinned if pinned else await _resolve(host)
    if not is_public_ip(ip):  # defence in depth: never connect to a non-public address
        raise CheckError(f"refusing to connect to non-public address {ip}")
    phases["dns_ms"] = round(dns_ms, 2)

    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), HTTP_TIMEOUT)
    except (OSError, asyncio.TimeoutError) as exc:
        raise CheckError(f"TCP connect to {ip}:{port} failed: {exc}") from exc
    t1 = time.perf_counter()
    phases["tcp_ms"] = round((t1 - t0) * 1000, 2)

    ssl_obj = None
    tls_error = None
    try:
        if scheme == "https":
            ctx = _ssl_context(verify, ["http/1.1"])
            try:
                await asyncio.wait_for(writer.start_tls(ctx, server_hostname=host), HTTP_TIMEOUT)
            except ssl.SSLError as exc:
                tls_error = str(exc)
                raise CheckError(f"TLS handshake failed: {exc.reason or exc}") from exc
            except (OSError, asyncio.TimeoutError) as exc:
                raise CheckError(f"TLS handshake failed: {exc}") from exc
            ssl_obj = writer.get_extra_info("ssl_object")
            t2 = time.perf_counter()
            phases["tls_ms"] = round((t2 - t1) * 1000, 2)
        else:
            t2 = t1
            phases["tls_ms"] = 0.0

        hosthdr = host if port in (80, 443) else f"{host}:{port}"
        if ":" in host:
            hosthdr = f"[{host}]" + (f":{port}" if port not in (80, 443) else "")
        req = (f"GET {path} HTTP/1.1\r\nHost: {hosthdr}\r\nUser-Agent: {USER_AGENT}\r\n"
               f"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        t3 = time.perf_counter()
        try:
            first = await asyncio.wait_for(reader.read(65536), HTTP_TIMEOUT)
        except asyncio.TimeoutError as exc:
            raise CheckError("timed out waiting for first byte") from exc
        if not first:
            raise CheckError("server closed connection without a response")
        t4 = time.perf_counter()
        phases["ttfb_ms"] = round((t4 - t3) * 1000, 2)

        buf = bytearray(first)
        deadline = time.perf_counter() + HTTP_TIMEOUT
        while len(buf) < MAX_RESPONSE_BYTES and time.perf_counter() < deadline:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), max(0.05, deadline - time.perf_counter()))
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
        t5 = time.perf_counter()
        phases["download_ms"] = round((t5 - t4) * 1000, 2)
        phases["total_ms"] = round((t5 - t0) * 1000 + dns_ms, 2)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except Exception:
            pass

    while b"\r\n\r\n" not in buf and len(buf) < MAX_RESPONSE_BYTES:
        break
    version, status, reason, headers = _parse_headers(bytes(buf))
    body_len = len(buf) - (buf.find(b"\r\n\r\n") + 4)
    info = {
        "ip": ip, "phases": phases, "http_version": version, "status": status, "reason": reason,
        "headers": headers, "response_bytes": max(0, body_len), "truncated": len(buf) >= MAX_RESPONSE_BYTES,
        "tls": None, "tls_error": tls_error,
    }
    if ssl_obj is not None:
        info["tls"] = {
            "version": ssl_obj.version(),
            "cipher": ssl_obj.cipher()[0] if ssl_obj.cipher() else None,
            "cipher_bits": ssl_obj.cipher()[2] if ssl_obj.cipher() else None,
            "alpn": ssl_obj.selected_alpn_protocol(),
            "peer_der": ssl_obj.getpeercert(binary_form=True),
            "chain_len": _chain_len(ssl_obj),
        }
    return info


def _chain_len(ssl_obj) -> int | None:
    for meth in ("get_verified_chain", "get_unverified_chain"):
        fn = getattr(getattr(ssl_obj, "_sslobj", None), meth, None) or getattr(ssl_obj, meth, None)
        if fn:
            try:
                chain = fn()
                if chain:
                    return len(chain)
            except Exception:
                continue
    return None


def _name(n: x509.Name) -> dict:
    out = {}
    for attr in n:
        out[attr.oid._name or attr.oid.dotted_string] = attr.value
    return out


def _cert_info(der: bytes, host: str, verified: bool) -> dict:
    cert = x509.load_der_x509_certificate(der)
    now = dt.datetime.now(dt.timezone.utc)
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(v) for v in san.get_values_for_type(x509.DNSName)] + \
               [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []
    subject = _name(cert.subject)
    issuer = _name(cert.issuer)
    self_signed = cert.subject == cert.issuer
    cn = subject.get("commonName")
    names = set(s.lower() for s in sans) | ({cn.lower()} if cn else set())

    def match(h: str) -> bool:
        h = h.lower()
        for n in names:
            if n == h:
                return True
            if n.startswith("*.") and h.count(".") == n.count(".") and h.endswith(n[1:]):
                return True
        return False

    try:
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        sig_alg = None
    try:
        fp = cert.fingerprint(hashes.SHA256()).hex(":")
    except Exception:
        fp = None
    try:
        ocsp = [str(d.access_location.value) for d in cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess).value if d.access_method._name == "OCSP"]
    except Exception:
        ocsp = []
    return {
        "subject": subject, "issuer": issuer, "common_name": cn, "san": sans,
        "serial": format(cert.serial_number, "x"),
        "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "days_remaining": (na - now).days, "expired": now > na, "not_yet_valid": now < nb,
        "self_signed": self_signed, "hostname_matches": match(host) if not is_ip_literal(host) else host in sans,
        "signature_algorithm": sig_alg, "signature_algorithm_oid": cert.signature_algorithm_oid._name,
        "public_key_type": type(cert.public_key()).__name__.replace("_", "").replace("PublicKey", ""),
        "public_key_bits": getattr(cert.public_key(), "key_size", None),
        "sha256_fingerprint": fp, "ocsp_responders": ocsp, "ocsp_stapling": None,
        "chain_verified": verified,
    }


async def _probe_h2(host: str, port: int, ip: str) -> str | None:
    """Separate handshake (to the same pinned IP) offering h2 to learn the server's preferred ALPN."""
    try:
        if not is_public_ip(ip):
            return None
        ctx = _ssl_context(False, ["h2", "http/1.1"])
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), HTTP_TIMEOUT)
        alpn = writer.get_extra_info("ssl_object").selected_alpn_protocol()
        writer.close()
        return alpn
    except Exception:
        return None


async def _fetch(scheme: str, host: str, port: int, path: str,
                 pinned: tuple[str, float] | None = None) -> tuple[dict, bool]:
    """Verified fetch first; if the TLS verification fails, retry unverified so we can still report."""
    try:
        return await _fetch_once(scheme, host, port, path, verify=True, pinned=pinned), True
    except CheckError as exc:
        if scheme == "https" and "TLS handshake failed" in str(exc):
            info = await _fetch_once(scheme, host, port, path, verify=False, pinned=pinned)
            info["tls_error"] = str(exc)
            return info, False
        raise


@router.post("/check", dependencies=[Depends(rate_limit)])
async def http_check(req: CheckRequest) -> dict:
    """Measure DNS / TCP / TLS / TTFB / download for a URL from this vantage point and inspect its certificate."""
    async with _gate.slot():
        return await _http_check(req)


async def _http_check(req: CheckRequest) -> dict:
    try:
        scheme, host, port, path = validate_url(req.url)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    redirects = []
    cur = (scheme, host, port, path)
    final = None
    verified = True
    for hop in range(MAX_REDIRECTS + 1):
        try:
            pinned = await _resolve(cur[1])
            info, verified = await _fetch(*cur, pinned=pinned)
        except CheckError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        url_here = f"{cur[0]}://{cur[1]}{'' if cur[2] in (80, 443) else ':' + str(cur[2])}{cur[3]}"
        loc = info["headers"].get("location")
        if 300 <= info["status"] < 400 and loc and hop < MAX_REDIRECTS:
            redirects.append({"url": url_here, "status": info["status"], "location": loc,
                              "ms": info["phases"]["total_ms"]})
            try:
                cur = validate_url(urljoin(url_here, loc))
            except ValidationError as exc:
                raise HTTPException(status_code=400, detail=f"redirect to disallowed target: {exc}")
            continue
        final = (url_here, info)
        break
    if final is None:
        raise HTTPException(status_code=400, detail="too many redirects")
    final_url, info = final
    scheme, host, port, path = cur

    # extra TTFB samples on the final URL
    samples = [info["phases"]]
    for _ in range(SAMPLES - 1):
        try:
            _ip_again, dns_again = await _resolve(host)  # re-validated; timing only, IP stays pinned
            more, _v = await _fetch(scheme, host, port, path, pinned=(pinned[0], dns_again))
            samples.append(more["phases"])
        except CheckError:
            break

    def stat(key: str) -> dict:
        vals = [s[key] for s in samples if key in s]
        return {"min": round(min(vals), 2), "avg": round(sum(vals) / len(vals), 2),
                "max": round(max(vals), 2)} if vals else None

    h = info["headers"]
    result = {
        "url": req.url, "final_url": final_url, "ip": info["ip"], "redirects": redirects,
        "status": info["status"], "reason": info["reason"], "http_version": "HTTP/" + info["http_version"],
        "server": h.get("server"), "content_type": h.get("content-type"),
        "response_bytes": info["response_bytes"], "truncated": info["truncated"],
        "samples": len(samples),
        "timing": {k: stat(k) for k in ("dns_ms", "tcp_ms", "tls_ms", "ttfb_ms", "download_ms", "total_ms")},
        "timing_first_sample": samples[0],
        "headers": {k: v for k, v in h.items() if k in (
            "server", "content-type", "content-length", "cache-control", "strict-transport-security",
            "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy",
            "alt-svc", "via", "cf-ray", "x-powered-by", "date")},
        "security": {
            "hsts": h.get("strict-transport-security"),
            "hsts_enabled": "strict-transport-security" in h,
            "https": scheme == "https",
        },
        "ssl": None,
    }
    if info["tls"]:
        tls = info["tls"]
        cert = _cert_info(tls["peer_der"], host, verified) if tls.get("peer_der") else None
        alpn = await _probe_h2(host, port, pinned[0])
        result["ssl"] = {
            "tls_version": tls["version"], "cipher": tls["cipher"], "cipher_bits": tls["cipher_bits"],
            "alpn_preferred": alpn, "http2_supported": alpn == "h2",
            "chain_length": tls["chain_len"], "verification_error": info.get("tls_error"),
            "certificate": cert,
        }
    return result
