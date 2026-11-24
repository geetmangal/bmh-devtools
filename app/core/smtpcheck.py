"""Read-only SMTP probe: banner, EHLO, STARTTLS, TLS version / cipher / certificate, then QUIT.

Safety:
* Never sends MAIL FROM, RCPT TO, DATA or anything else: every outgoing line goes through ``_Conn.send`` which only
  allows EHLO, STARTTLS and QUIT (``ForbiddenCommand`` otherwise).
* The target is resolved through ``target.resolve_public`` (SSRF guard: public addresses only). Tests may inject
  ``resolve_host`` (an async callable host -> list of IPs) to reach a loopback fixture; production never passes it.
* Disabled unless env ``BMH_TOOLS_SMTP_ENABLED`` is 1/true/yes/on (many hosts block outbound port 25).
* Total time budget 8 s for the whole conversation."""
from __future__ import annotations

import asyncio
import datetime as dt
import os
import ssl
import time
from typing import Awaitable, Callable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from app.core.mailcheck.models import CheckResult, error_result
from app.core.target import TargetError, parse_target, resolve_public
from app.core.validate import ValidationError, is_ip_literal

EHLO_NAME = "bmh-tools-check.bookmyhost.com"
BUDGET = 8.0
ALLOWED_VERBS = frozenset({"EHLO", "STARTTLS", "QUIT"})
DEFAULT_PORTS = (25, 587, 2525)
MAX_REPLY_LINES = 100


class ForbiddenCommand(Exception):
    """Raised if anything other than EHLO / STARTTLS / QUIT would be sent."""


def enabled() -> bool:
    return os.environ.get("BMH_TOOLS_SMTP_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on")


async def _default_resolve(host: str) -> list[str]:
    value, is_ip = parse_target(host)
    return [value] if is_ip else await resolve_public(value)


class _Conn:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer
        self.sent: list[str] = []

    async def send(self, line: str) -> None:
        verb = line.strip().split(" ", 1)[0].upper()
        if verb not in ALLOWED_VERBS or "\r" in line or "\n" in line:
            raise ForbiddenCommand(f"refusing to send {verb or 'empty'!r}: this probe never sends mail commands")
        self.sent.append(line)
        self.writer.write(line.encode("ascii") + b"\r\n")
        await self.writer.drain()

    async def reply(self) -> tuple[int, list[str]]:
        lines: list[str] = []
        while len(lines) < MAX_REPLY_LINES:
            raw = await self.reader.readline()
            if not raw:
                raise ConnectionError("connection closed by server")
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if len(line) < 3 or not line[:3].isdigit():
                raise ConnectionError("not an SMTP reply")
            lines.append(line)
            if len(line) == 3 or line[3] == " ":
                return int(line[:3]), [x[4:] for x in lines]
        raise ConnectionError("reply too long")

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:  # noqa: BLE001
            pass


def parse_extensions(lines: list[str]) -> dict[str, str]:
    ext: dict[str, str] = {}
    for line in lines[1:]:
        k, _, v = line.partition(" ")
        if k:
            ext[k.upper()] = v
    return ext


def name_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def describe_cert(der: bytes) -> dict:
    c = x509.load_der_x509_certificate(der)

    def cn(name: x509.Name) -> str | None:
        v = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return v[0].value if v else None

    try:
        sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    pk = c.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key = f"RSA {pk.key_size}"
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key = f"EC {pk.curve.name}"
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        key = "Ed25519"
    else:
        key = type(pk).__name__
    now = dt.datetime.now(dt.timezone.utc)
    org = c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return {"subject": cn(c.subject), "sans": list(sans), "issuer": cn(c.issuer) or (org[0].value if org else None),
            "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
            "days_left": (c.not_valid_after_utc - now).days, "key": key, "self_signed": c.subject == c.issuer,
            "signature": c.signature_hash_algorithm.name if c.signature_hash_algorithm else None}


def _ctx(verify: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False  # we compare names ourselves so we can report mismatches instead of aborting
    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _conversation(ip: str, port: int, host: str, verify: bool, st: dict) -> None:
    """One full session. Fills ``st`` (steps, banner, extensions, tls...) as it goes so a timeout keeps partial data."""
    steps = st["steps"]

    async def step(name: str, coro, detail=lambda r: None):
        t0 = time.perf_counter()
        try:
            out = await coro
        except BaseException as exc:
            steps.append({"step": name, "ok": False, "ms": round((time.perf_counter() - t0) * 1000, 1), "detail": type(exc).__name__})
            raise
        steps.append({"step": name, "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1), "detail": detail(out)})
        return out

    reader, writer = await step("connect", asyncio.open_connection(ip, port), lambda r: f"{ip}:{port}")
    conn = _Conn(reader, writer)
    st["conn"] = conn
    try:
        code, lines = await step("banner", conn.reply(), lambda r: r[1][0][:120] if r[1] else "")
        st["banner"] = " / ".join(lines)[:300]
        st["banner_code"] = code
        if code != 220:
            return
        await conn.send(f"EHLO {EHLO_NAME}")
        code, lines = await step("ehlo", conn.reply(), lambda r: f"{r[0]}, {len(r[1]) - 1} extensions")
        st["ehlo_code"] = code
        if code != 250:
            await _quit(conn, steps)
            return
        st["ehlo_hostname"] = lines[0].split(" ", 1)[0]
        st["extensions"] = parse_extensions(lines)
        st["starttls"] = "STARTTLS" in st["extensions"]
        if st["starttls"]:
            await conn.send("STARTTLS")
            code, lines = await step("starttls", conn.reply(), lambda r: f"{r[0]} {r[1][0][:60]}")
            if code == 220:
                sni = None if is_ip_literal(host) else host
                try:
                    await step("tls_handshake", writer.start_tls(_ctx(verify), server_hostname=sni), lambda r: None)
                except ssl.SSLCertVerificationError as exc:
                    st["verify_error"] = exc.verify_message or str(exc)
                    raise
                except (ssl.SSLError, OSError) as exc:
                    st["tls_error"] = f"{type(exc).__name__}: {getattr(exc, 'reason', None) or exc}"[:200]
                    return
                so = writer.get_extra_info("ssl_object")
                cipher = so.cipher()
                st["tls"] = {"version": so.version(), "cipher": cipher[0], "bits": cipher[2], "trusted": verify}
                der = so.getpeercert(binary_form=True)
                if der:
                    st["tls"]["cert"] = describe_cert(der)
                await conn.send(f"EHLO {EHLO_NAME}")
                code, lines = await step("ehlo_tls", conn.reply(), lambda r: f"{r[0]}, {len(r[1]) - 1} extensions")
                if code == 250:
                    st["extensions_tls"] = parse_extensions(lines)
        await _quit(conn, steps)
    finally:
        conn.close()


async def _quit(conn: _Conn, steps: list[dict]) -> None:
    t0 = time.perf_counter()
    try:
        await conn.send("QUIT")
        code, _ = await asyncio.wait_for(conn.reply(), 1.5)
        steps.append({"step": "quit", "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1), "detail": str(code)})
    except (ConnectionError, asyncio.TimeoutError, OSError):
        steps.append({"step": "quit", "ok": False, "ms": round((time.perf_counter() - t0) * 1000, 1), "detail": "no reply"})


async def check(host_or_mx: str, port: int = 25, *, resolve_host: Callable[[str], Awaitable[list[str]]] | None = None,
                allowed_ports: tuple[int, ...] | None = DEFAULT_PORTS, budget: float = BUDGET) -> CheckResult:
    host = (host_or_mx or "").strip().rstrip(".").lower()
    res = CheckResult("smtp", host)
    if not enabled():
        res.add("smtp_disabled", "info", "Live SMTP test is not available from this server",
                "The SMTP connection test is switched off on this installation (outbound mail ports are often blocked on hosting networks), "
                "so we did not connect to your mail server.",
                ["Run it yourself: openssl s_client -starttls smtp -connect <mailserver>:25  (or  swaks --to you@example.com --server <mailserver> --tls)."])
        res.data = {"applicable": False, "enabled": False}
        return res.finalize("The SMTP test is not available from this server.", score=100, status="info")
    if allowed_ports is not None and port not in allowed_ports:
        raise ValidationError(f"port must be one of {', '.join(map(str, allowed_ports))}")
    try:
        ips = await (resolve_host or _default_resolve)(host)
    except (TargetError, ValidationError) as exc:
        res.add("smtp_target_refused", "fail", "This host cannot be tested", str(exc),
                ["Only public mail servers can be tested. Use the MX host name shown in the MX check."])
        res.data = {"host": host, "port": port, "steps": []}
        return res.finalize(f"Refused: {exc}")
    st: dict = {"steps": [], "tls": None, "starttls": None, "extensions": {}}
    t_all = time.perf_counter()
    err: str | None = None
    used_ip = ips[0]
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget
    for ip in ips[:2]:
        used_ip = ip
        st.update(steps=[], tls=None, starttls=None, extensions={}, verify_error=None, tls_error=None)
        try:
            try:
                await asyncio.wait_for(_conversation(ip, port, host, True, st), max(0.1, deadline - loop.time()))
            except ssl.SSLCertVerificationError:
                verify_error = st.get("verify_error")
                st.update(steps=[], tls=None, starttls=None, extensions={})
                await asyncio.wait_for(_conversation(ip, port, host, False, st), max(0.1, deadline - loop.time()))
                vstep = {"step": "verify_chain", "ok": False, "ms": 0.0, "detail": verify_error}
                at = next((i for i, x in enumerate(st["steps"]) if x["step"] == "tls_handshake"), len(st["steps"]) - 1)
                st["steps"].insert(at + 1, vstep)
                if st.get("tls"):
                    st["tls"]["trusted"] = False
                    st["tls"]["verify_error"] = verify_error
            err = None
            break
        except asyncio.TimeoutError:
            err = "timeout"
            break
        except (ConnectionError, OSError, ssl.SSLError, TimeoutError) as exc:
            err = f"{type(exc).__name__}: {exc}"[:160]
            if not st["steps"] or st["steps"][-1]["step"] != "connect":
                break
    conn = st.pop("conn", None)
    if conn:
        conn.close()
    total = round((time.perf_counter() - t_all) * 1000, 1)
    res.timings_ms["total"] = total
    res.data = {"applicable": True, "host": host, "ip": used_ip, "ips": ips, "port": port, "banner": st.get("banner"),
                "ehlo_hostname": st.get("ehlo_hostname"), "extensions": st.get("extensions", {}),
                "extensions_after_tls": st.get("extensions_tls"), "starttls": st.get("starttls"), "tls": st.get("tls"),
                "steps": st["steps"], "total_ms": total}
    _findings(res, st, err, host, port)
    return res.finalize(_summary(res, st, err, host))


def _findings(res: CheckResult, st: dict, err: str | None, host: str, port: int) -> None:
    steps = st["steps"]
    connected = any(s["step"] == "connect" and s["ok"] for s in steps)
    if err == "timeout":
        res.add("smtp_timeout", "fail" if not connected else "warn", "The mail server did not answer in time",
                f"We waited {BUDGET:.0f} seconds. Either the server is down, very slow, or a firewall silently drops connections to port {port}.",
                ["Check the mail server is running and port 25 is open in its firewall.",
                 "Some hosts only allow port 25 from certain addresses; check your firewall / security group rules."])
    elif err and not connected:
        res.add("smtp_unreachable", "fail", "Could not connect to the mail server",
                f"A connection to {host} on port {port} failed ({err}). Other mail servers cannot deliver mail to you through it either.",
                ["Make sure the mail software is running and listening on port 25.",
                 "Open port 25 inbound in the server firewall and in any cloud security group.",
                 "Check that the MX host name points to the right IP address."])
    if not connected:
        return
    if st.get("banner_code") not in (None, 220):
        res.add("smtp_banner_bad", "fail", f"The server greeted us with {st.get('banner_code')}, not 220",
                f"Server said: {st.get('banner')}. Codes starting with 4 or 5 mean it is refusing or temporarily not accepting connections.",
                ["Read the message above; it normally explains (for example 'service not available', or our address is blocked)."])
        return
    if st.get("ehlo_code") not in (None, 250):
        res.add("smtp_ehlo_failed", "warn", "The server rejected EHLO", "Modern mail servers must support EHLO (the extended greeting).",
                ["Check the mail server configuration."])
        return
    if err:
        res.add("smtp_interrupted", "warn", "The conversation ended early", f"The connection broke during the test ({err}).",
                ["Check the mail server logs; it may limit connections from unknown clients."])
    tls = st.get("tls")
    if st.get("starttls") is False:
        res.add("smtp_no_starttls", "fail", "The server does not offer encryption (STARTTLS)",
                "Mail sent to this server travels in plain text, so anyone on the path can read it. Gmail, Microsoft and others show "
                "warnings or may refuse to deliver to servers without TLS.",
                ["Install a TLS certificate on the mail server (a free Let's Encrypt certificate works).",
                 "Enable STARTTLS in the mail software (Postfix: smtpd_tls_cert_file / smtpd_tls_key_file and smtpd_tls_security_level = may)."])
    elif st.get("tls_error"):
        res.add("smtp_tls_failed", "fail", "STARTTLS is offered but the encrypted session could not be set up",
                f"The handshake failed ({st['tls_error']}). The server may only support outdated TLS (1.0/1.1) or have a broken certificate/key setup.",
                ["Enable TLS 1.2 and 1.3 on the mail server and check the certificate files are readable.", "Restart the mail software and test again."])
    if tls:
        c = tls.get("cert") or {}
        res.add("smtp_tls_ok", "pass", f"Encrypted with {tls['version']} ({tls['cipher']})", "The server accepts encrypted connections with a modern protocol.")
        if c:
            names = c["sans"] or ([c["subject"]] if c["subject"] else [])
            if not is_ip_literal(host) and names and not name_matches(host, names):
                res.add("smtp_cert_name_mismatch", "warn", f"The certificate is not valid for {host}",
                        f"It is issued to {', '.join(names[:4])}. Most servers still deliver (they do not insist on a matching name), but senders using "
                        "MTA-STS or DANE will refuse.",
                        [f"Get a certificate that lists {host} (a Let's Encrypt certificate is free).", "Install it in the mail software and reload."],
                        host=host, names=names)
            if c["days_left"] < 0:
                res.add("smtp_cert_expired", "fail", f"The certificate expired {-c['days_left']} day(s) ago",
                        "Expired certificates make strict senders (MTA-STS / DANE) refuse delivery and others fall back to unencrypted mail.",
                        ["Renew the certificate now and reload the mail software.", "Set up automatic renewal (certbot renew + a deploy hook) so it does not happen again."],
                        not_after=c["not_after"])
            elif c["days_left"] < 14:
                res.add("smtp_cert_expiring", "warn", f"The certificate expires in {c['days_left']} day(s)", "Renew it before it expires.",
                        ["Renew the certificate and reload the mail software.", "Check automatic renewal works."], not_after=c["not_after"])
            if tls.get("trusted") is False:
                why = tls.get("verify_error") or "unknown issuer"
                res.add("smtp_cert_untrusted", "warn", "The certificate is not trusted by public authorities" if not c["self_signed"] else "The certificate is self-signed",
                        f"Verification failed: {why}. Mail servers usually still deliver (they accept any certificate for opportunistic encryption), "
                        "but senders with strict rules (MTA-STS, DANE) will refuse, and it looks unprofessional.",
                        ["Use a certificate from a public CA such as Let's Encrypt.", "Install the full chain (certificate + intermediate) in the mail software."],
                        reason=why)


def _summary(res: CheckResult, st: dict, err: str | None, host: str) -> str:
    fails = [f for f in res.findings if f.status == "fail"]
    if fails:
        return f"{host}: {fails[0].title}."
    tls = st.get("tls")
    if tls:
        trusted = "" if tls.get("trusted") else " (certificate not publicly trusted)"
        return f"{host} accepts mail over {tls['version']}{trusted}."
    return f"{host} answered but could not be fully tested."
