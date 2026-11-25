"""One injectable async DNS interface for all mail checks.

``DnsResolver`` is the production implementation (thin wrapper over ``dns.asyncresolver``: timeout +
lifetime, typed answers, NXDOMAIN and NOANSWER kept distinct). ``FakeResolver`` is a dict-backed test
double so tests never touch the network.

Resolver servers: env ``BMH_TOOLS_MAILCHECK_RESOLVERS`` (comma separated IP or IP:port); default is the system
resolver. DNSSEC "AD" results are only meaningful when that resolver validates."""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Protocol

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver

from app.core.validate import is_public_ip

# status values
OK, NXDOMAIN, NOANSWER, TIMEOUT, SERVFAIL, ERROR = "ok", "nxdomain", "noanswer", "timeout", "servfail", "error"


@dataclass
class DnsResult:
    name: str
    rtype: str
    status: str = OK
    records: list[str] = field(default_factory=list)       # rdata as text (TXT: strings joined)
    txt_strings: list[list[str]] = field(default_factory=list)  # TXT only: the individual strings
    ttl: int | None = None
    cname_chain: list[str] = field(default_factory=list)   # CNAMEs followed to reach the answer
    ad: bool = False                                       # resolver says DNSSEC-validated
    aa: bool = False                                       # authoritative answer (query_at only)

    @property
    def ok(self) -> bool:
        return self.status == OK and bool(self.records)

    @property
    def exists(self) -> bool:
        """The name exists (even if it has no record of this type)."""
        return self.status in (OK, NOANSWER)

    @property
    def failed(self) -> bool:
        """Resolver-level failure (we do not know the answer)."""
        return self.status in (TIMEOUT, SERVFAIL, ERROR)


class Resolver(Protocol):
    async def query(self, name: str, rtype: str, *, dnssec: bool = False) -> DnsResult: ...
    async def query_at(self, server: str, name: str, rtype: str) -> DnsResult: ...


def _strip(name: str) -> str:
    return name.rstrip(".").lower()


def rdata_text(rr, rtype: str) -> str:
    if rtype in ("NS", "CNAME", "PTR"):
        return _strip(rr.target.to_text())
    if rtype == "MX":
        host = _strip(rr.exchange.to_text())
        return f"{rr.preference} {host or '.'}"
    if rtype == "TXT":
        return b"".join(rr.strings).decode("utf-8", "replace")
    if rtype == "SOA":
        return (f"{_strip(rr.mname.to_text())} {_strip(rr.rname.to_text())} {rr.serial} "
                f"{rr.refresh} {rr.retry} {rr.expire} {rr.minimum}")
    if rtype == "CAA":
        return f'{rr.flags} {rr.tag.decode("ascii", "replace")} {rr.value.decode("utf-8", "replace")}'
    return rr.to_text()


def _fill(res: DnsResult, rrsets, rtype: str) -> None:
    want = dns.rdatatype.from_text(rtype)
    for rrset in rrsets:
        if rrset.rdtype == dns.rdatatype.CNAME and rtype != "CNAME":
            res.cname_chain.append(_strip(rrset.name.to_text()))
        elif rrset.rdtype == want:
            res.ttl = rrset.ttl
            for rr in rrset:
                res.records.append(rdata_text(rr, rtype))
                if rtype == "TXT":
                    res.txt_strings.append([s.decode("utf-8", "replace") for s in rr.strings])


def parse_nameserver(spec: str):
    """'1.2.3.4', '1.2.3.4:5335', '2001:db8::1' or '[2001:db8::1]:5335' -> what dnspython accepts.
    A non-default port is needed for the local unbound sidecar (127.0.0.1:5335)."""
    import ipaddress

    import dns.nameserver
    s = spec.strip()
    host, port = s, 53
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif s.count(":") == 1:
        host, p = s.split(":")
        port = int(p)
    ipaddress.ip_address(host)  # ValueError on garbage
    if not 0 < port < 65536:
        raise ValueError(f"bad port in nameserver {spec!r}")
    return host if port == 53 else dns.nameserver.Do53Nameserver(host, port)


def default_nameservers() -> list[str] | None:
    raw = os.environ.get("BMH_TOOLS_MAILCHECK_RESOLVERS", "").strip()
    ips = [p.strip() for p in raw.split(",") if p.strip()]
    return ips or None


class DnsResolver:
    """Production resolver. ``timeout`` is per attempt, ``lifetime`` the total per query."""

    def __init__(self, nameservers: list[str] | None = None, timeout: float = 2.0, lifetime: float = 4.0) -> None:
        self.nameservers = nameservers if nameservers is not None else default_nameservers()
        self.timeout = timeout
        self.lifetime = lifetime

    def _make(self) -> dns.asyncresolver.Resolver:
        if self.nameservers:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = [parse_nameserver(n) for n in self.nameservers]
        else:
            try:
                r = dns.asyncresolver.Resolver(configure=True)
            except dns.resolver.NoResolverConfiguration:
                r = dns.asyncresolver.Resolver(configure=False)
                r.nameservers = ["1.1.1.1", "8.8.8.8"]
        r.timeout = self.timeout
        r.lifetime = self.lifetime
        return r

    async def query(self, name: str, rtype: str, *, dnssec: bool = False) -> DnsResult:
        name = _strip(name)
        rtype = rtype.upper()
        res = DnsResult(name, rtype)
        r = self._make()
        if dnssec:
            r.use_edns(0, dns.flags.DO, 1232)
            r.flags = dns.flags.RD | dns.flags.AD
        try:
            ans = await r.resolve(name, rtype, raise_on_no_answer=True)
        except dns.resolver.NXDOMAIN:
            res.status = NXDOMAIN
        except dns.resolver.NoAnswer:
            res.status = NOANSWER
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, asyncio.TimeoutError):
            res.status = TIMEOUT
        except dns.resolver.NoNameservers:
            res.status = SERVFAIL
        except (dns.exception.DNSException, OSError, ValueError):
            res.status = ERROR
        else:
            _fill(res, ans.response.answer, rtype)
            res.ad = bool(ans.response.flags & dns.flags.AD)
            if not res.records:
                res.status = NOANSWER
        return res

    async def query_at(self, server: str, name: str, rtype: str) -> DnsResult:
        """Ask one specific server directly (no recursion), e.g. to test a delegated nameserver.
        Refuses non-public server addresses (a zone can delegate to an internal address)."""
        name = _strip(name)
        rtype = rtype.upper()
        res = DnsResult(name, rtype)
        if not is_public_ip(server):
            res.status = ERROR
            return res
        q = dns.message.make_query(name, rtype, use_edns=0, want_dnssec=False)
        q.flags &= ~dns.flags.RD
        try:
            resp, _tcp = await asyncio.wait_for(
                dns.asyncquery.udp_with_fallback(q, server, timeout=self.timeout), self.lifetime)
        except (asyncio.TimeoutError, dns.exception.Timeout):
            res.status = TIMEOUT
            return res
        except (dns.exception.DNSException, OSError, ValueError):
            res.status = ERROR
            return res
        res.aa = bool(resp.flags & dns.flags.AA)
        rc = resp.rcode()
        if rc == dns.rcode.NXDOMAIN:
            res.status = NXDOMAIN
        elif rc != dns.rcode.NOERROR:
            res.status = SERVFAIL  # REFUSED / SERVFAIL etc: the server will not answer for this zone
        else:
            _fill(res, resp.answer, rtype)
            res.status = OK if res.records else NOANSWER
        return res


_default: DnsResolver | None = None


def get_default_resolver() -> DnsResolver:
    global _default
    if _default is None:
        _default = DnsResolver()
    return _default


# --------------------------------------------------------------------------------------------
# Test double
# --------------------------------------------------------------------------------------------
_STATUS_WORDS = {"NXDOMAIN": NXDOMAIN, "TIMEOUT": TIMEOUT, "SERVFAIL": SERVFAIL, "NOANSWER": NOANSWER, "ERROR": ERROR}


class FakeResolver:
    """Dict-backed resolver for tests.

    zone keys: ``"name/TYPE"`` or ``("name", "TYPE")``; values: a list of rdata strings (TXT items may be a
    tuple of strings), or a status word ("NXDOMAIN", "TIMEOUT", "SERVFAIL", "NOANSWER").
    A name with any record but not the asked type answers NOANSWER; a completely unknown name is NXDOMAIN.
    CNAMEs are followed. ``"name/TYPE@ip"`` overrides ``query_at`` for that server (default: same as query).
    ``ad_names`` = names for which DNSSEC queries come back with the AD flag."""

    def __init__(self, zone: dict | None = None, ad_names: tuple[str, ...] | set[str] = ()) -> None:
        self.zone: dict[tuple[str, str, str], object] = {}
        for k, v in (zone or {}).items():
            at = ""
            if isinstance(k, tuple):
                name, rtype = k[0], k[1]
                if len(k) > 2:
                    at = k[2]
            else:
                name, _, rtype = k.partition("/")
                rtype, _, at = rtype.partition("@")
            self.zone[(_strip(name), rtype.upper(), at)] = v
        self.ad_names = {_strip(n) for n in ad_names}
        self.calls: list[tuple] = []

    def _lookup(self, name: str, rtype: str, at: str = "") -> DnsResult:
        name = _strip(name)
        res = DnsResult(name, rtype)
        seen = 0
        while True:
            val = self.zone.get((name, rtype, at))
            if val is None and at:
                val = self.zone.get((name, rtype, ""))
            if val is None and rtype != "CNAME":
                cn = self.zone.get((name, "CNAME", ""))
                if isinstance(cn, list) and cn and seen < 8:
                    res.cname_chain.append(name)
                    name = _strip(cn[0])
                    seen += 1
                    continue
            break
        if val is None:
            names = {k[0] for k in self.zone}
            exists = name in names or any(n.endswith("." + name) for n in names)
            res.status = NOANSWER if exists else NXDOMAIN
            return res
        if isinstance(val, str):
            res.status = _STATUS_WORDS[val.upper()]
            return res
        if not val:
            res.status = NOANSWER
            return res
        for item in val:
            if rtype == "TXT":
                strings = [item] if isinstance(item, str) else list(item)
                res.txt_strings.append(strings)
                res.records.append("".join(strings))
            else:
                res.records.append(item if isinstance(item, str) else " ".join(map(str, item)))
        res.ttl = 300
        res.aa = True
        return res

    async def query(self, name: str, rtype: str, *, dnssec: bool = False) -> DnsResult:
        self.calls.append((_strip(name), rtype.upper()))
        res = self._lookup(name, rtype.upper())
        if dnssec and res.status == OK and _strip(name) in self.ad_names:
            res.ad = True
        return res

    async def query_at(self, server: str, name: str, rtype: str) -> DnsResult:
        self.calls.append((_strip(name), rtype.upper(), server))
        return self._lookup(name, rtype.upper(), server)
