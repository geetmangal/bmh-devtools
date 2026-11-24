"""SMTP probe against a local aiosmtpd fixture. The loopback is reached ONLY through the injectable
``resolve_host`` hook; the SSRF guard itself is never weakened."""
import asyncio
import datetime as dt
import socket
import ssl

import pytest
from aiosmtpd.controller import Controller
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core import smtpcheck
from app.core.validate import ValidationError

HOST = "mail.test.example"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def loopback(_host):
    return ["127.0.0.1"]


def ids(res):
    return {f.id for f in res.findings}


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST), x509.DNSName("*.wild.example")]), critical=False)
            .sign(key, hashes.SHA256()))
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return d / "c.pem", d / "k.pem"


class Recorder:
    """aiosmtpd handler that records any attempt to start a mail transaction."""

    def __init__(self):
        self.events = []

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        self.events.append("MAIL")
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        self.events.append("RCPT")
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.events.append("DATA")
        return "250 OK"


@pytest.fixture
def server_factory():
    started = []

    def make(cert=None):
        rec = Recorder()
        kw = {}
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*map(str, cert))
            kw["tls_context"] = ctx
        port = free_port()
        c = Controller(rec, hostname="127.0.0.1", port=port, server_hostname=HOST, **kw)
        c.start()
        started.append(c)
        return port, rec

    yield make
    for c in started:
        c.stop()


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("BMH_TOOLS_SMTP_ENABLED", "1")


async def probe(host, port):
    return await smtpcheck.check(host, port, resolve_host=loopback, allowed_ports=None)


async def test_starttls_on_self_signed(server_factory, cert_files, enabled):
    port, rec = server_factory(cert_files)
    res = await probe(HOST, port)
    d = res.data
    assert d["starttls"] is True and d["banner"] and "STARTTLS" in d["extensions"] and d["ehlo_hostname"] == HOST
    assert d["tls"]["version"] in ("TLSv1.2", "TLSv1.3") and d["tls"]["cipher"] and d["tls"]["bits"]
    cert = d["tls"]["cert"]
    assert cert["subject"] == HOST and HOST in cert["sans"] and cert["self_signed"] is True and cert["days_left"] in (89, 90) and cert["key"] == "RSA 2048"
    assert d["tls"]["trusted"] is False and "smtp_cert_untrusted" in ids(res) and "smtp_cert_name_mismatch" not in ids(res)
    assert "smtp_tls_ok" in ids(res) and res.status == "warn" and "TLSv1" in res.summary
    names = [s["step"] for s in d["steps"]]
    assert names[:2] == ["connect", "banner"] and {"ehlo", "starttls", "tls_handshake", "ehlo_tls", "quit"} <= set(names)
    assert all(isinstance(s["ms"], float) for s in d["steps"]) and res.timings_ms["total"] > 0
    assert rec.events == []  # never MAIL / RCPT / DATA


async def test_certificate_name_mismatch(server_factory, cert_files, enabled):
    port, _ = server_factory(cert_files)
    res = await probe("other.example.org", port)
    assert "smtp_cert_name_mismatch" in ids(res)
    wild = await probe("anything.wild.example", port)
    assert "smtp_cert_name_mismatch" not in ids(wild)


async def test_no_starttls_offered(server_factory, enabled):
    port, rec = server_factory()
    res = await probe(HOST, port)
    assert res.data["starttls"] is False and res.data["tls"] is None
    f = next(f for f in res.findings if f.id == "smtp_no_starttls")
    assert f.status == "fail" and res.status == "fail" and rec.events == []
    assert [s["step"] for s in res.data["steps"]][-1] == "quit"


async def test_connection_refused_is_a_clear_failure(enabled):
    res = await probe(HOST, free_port())
    assert "smtp_unreachable" in ids(res) and res.status == "fail"


async def test_timeout_budget(enabled):
    async def black_hole(reader, writer):  # accepts, never speaks
        await asyncio.sleep(30)

    srv = await asyncio.start_server(black_hole, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    try:
        res = await smtpcheck.check(HOST, port, resolve_host=loopback, allowed_ports=None, budget=0.4)
    finally:
        srv.close()
    assert "smtp_timeout" in ids(res) and res.timings_ms["total"] < 3000
    assert res.data["steps"][0]["step"] == "connect"


async def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("BMH_TOOLS_SMTP_ENABLED", raising=False)

    async def must_not_resolve(_h):
        raise AssertionError("no network activity expected when disabled")

    res = await smtpcheck.check("mail.example.com", resolve_host=must_not_resolve)
    assert res.status == "info" and res.data["applicable"] is False and "not available" in res.summary
    monkeypatch.setenv("BMH_TOOLS_SMTP_ENABLED", "0")
    assert (await smtpcheck.check("mail.example.com", resolve_host=must_not_resolve)).status == "info"


async def test_never_sends_mail_commands():
    class W:
        def __init__(self):
            self.buf = b""

        def write(self, b):
            self.buf += b

        async def drain(self):
            pass

    w = W()
    conn = smtpcheck._Conn(None, w)
    for bad in ("MAIL FROM:<a@example.com>", "rcpt to:<b@example.com>", "DATA", "VRFY root", "EXPN list", "AUTH PLAIN x", "RSET", "NOOP",
                "EHLO x\r\nMAIL FROM:<a@b>", "  mail from:<x>"):
        with pytest.raises(smtpcheck.ForbiddenCommand):
            await conn.send(bad)
    assert w.buf == b""
    for ok in ("EHLO bmh-tools-check.bookmyhost.com", "STARTTLS", "QUIT"):
        await conn.send(ok)
    assert w.buf.count(b"\r\n") == 3 and smtpcheck.ALLOWED_VERBS == {"EHLO", "STARTTLS", "QUIT"}


async def test_ssrf_guard_stays_on_in_production_path(enabled):
    for target in ("127.0.0.1", "localhost", "10.0.0.5", "169.254.169.254", "::1", "intranet"):
        res = await smtpcheck.check(target, 25)
        assert "smtp_target_refused" in ids(res) and res.status == "fail", target
        assert res.data["steps"] == []
    with pytest.raises(ValidationError):
        await smtpcheck.check("mail.example.com", 22)
    with pytest.raises(ValidationError):
        await smtpcheck.check("mail.example.com", 3306)


async def test_resolved_private_address_is_refused(enabled, monkeypatch):
    async def fake_resolve_public(host, timeout=8.0):
        from app.core.target import TargetError
        raise TargetError(f"{host} resolves to a non-public address (10.0.0.1); refusing", 422)

    monkeypatch.setattr(smtpcheck, "resolve_public", fake_resolve_public)
    res = await smtpcheck.check("sneaky.example.com", 25)
    assert "smtp_target_refused" in ids(res)


def test_helpers():
    assert smtpcheck.name_matches("mx.example.com", ["*.example.com"]) and not smtpcheck.name_matches("a.b.example.com", ["*.example.com"])
    assert smtpcheck.name_matches("MX.example.com.", ["mx.example.com"]) and not smtpcheck.name_matches("x.com", [])
    ext = smtpcheck.parse_extensions(["mail.example.com greets you", "SIZE 1000", "8BITMIME", "STARTTLS", "AUTH PLAIN LOGIN"])
    assert ext == {"SIZE": "1000", "8BITMIME": "", "STARTTLS": "", "AUTH": "PLAIN LOGIN"}
