"""DNS records check: A/AAAA/NS/SOA/TXT/CAA/MX/CNAME in one call plus NS health, SOA sanity, CAA and a basic DNSSEC state.

DNSSEC is deliberately basic: "signed" (DS at the parent + DNSKEY + the resolver set the AD flag), "unsigned",
"partial" (DNSKEY but no DS), "broken" (DS but no DNSKEY, or a validating resolver answers SERVFAIL) and
"unverified" (DS+DNSKEY present but our resolver does not validate, so AD is not set). A real validation of the chain of
trust needs a validating resolver: point BMH_TOOLS_MAILCHECK_RESOLVERS at one."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import time

from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.resolver import Resolver, get_default_resolver
from app.core.validate import is_public_ip

RTYPES = ["A", "AAAA", "NS", "SOA", "TXT", "CAA", "MX", "CNAME"]
NS_PROBE_LIMIT = 8
NS_PROBE_CONCURRENCY = 6
# RFC 1912 / RIPE-203 style sane ranges (seconds)
SOA_RANGES = {"refresh": (1200, 43200), "retry": (120, 7200), "expire": (1209600, 2419200), "minimum": (300, 86400)}
KNOWN_CAA_TAGS = {"issue", "issuewild", "iodef", "contactemail", "contactphone"}
CA_NAMES = {
    "letsencrypt.org": "Let's Encrypt", "digicert.com": "DigiCert", "sectigo.com": "Sectigo", "comodoca.com": "Sectigo (Comodo)",
    "globalsign.com": "GlobalSign", "pki.goog": "Google Trust Services", "amazon.com": "Amazon", "amazontrust.com": "Amazon",
    "amazonaws.com": "Amazon", "ssl.com": "SSL.com", "godaddy.com": "GoDaddy", "starfieldtech.com": "GoDaddy (Starfield)",
    "buypass.com": "Buypass", "zerossl.com": "ZeroSSL", "entrust.net": "Entrust", "certum.pl": "Certum", "actalis.it": "Actalis",
    "identrust.com": "IdenTrust", "swisssign.com": "SwissSign", "telia.com": "Telia",
}


def parse_soa(text: str) -> dict | None:
    p = text.split()
    if len(p) != 7 or not all(x.isdigit() for x in p[2:]):
        return None
    return {"mname": p[0], "rname": p[1], "serial": int(p[2]), "refresh": int(p[3]), "retry": int(p[4]),
            "expire": int(p[5]), "minimum": int(p[6])}


def serial_format(serial: int) -> str:
    s = str(serial)
    if len(s) == 10:
        y, m, d = int(s[:4]), int(s[4:6]), int(s[6:8])
        if 1990 <= y <= 2100 and 1 <= m <= 12 and 1 <= d <= 31:
            return "date"  # YYYYMMDDnn
    if 1_000_000_000 <= serial <= 4_294_967_295 and len(s) == 10:
        return "unix-timestamp"
    return "counter"


def parse_caa(records: list[str]) -> list[dict]:
    out = []
    for rec in records:
        m = re.match(r"^\s*(\d+)\s+([A-Za-z0-9]+)\s+(.*?)\s*$", rec)
        if not m:
            out.append({"raw": rec, "valid": False})
            continue
        value = m.group(3).strip().strip('"')
        out.append({"raw": rec, "valid": True, "flags": int(m.group(1)), "tag": m.group(2).lower(), "value": value,
                    "ca": value.split(";")[0].strip().lower() if m.group(2).lower() in ("issue", "issuewild") else None})
    return out


def _prefix_key(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))


async def _check_ns(r: Resolver, domain: str, hosts: list[str], res: CheckResult) -> dict:
    hosts = hosts[:NS_PROBE_LIMIT]
    sem = asyncio.Semaphore(NS_PROBE_CONCURRENCY)

    async def one(h: str) -> dict:
        cname, a, aaaa = await asyncio.gather(r.query(h, "CNAME"), r.query(h, "A"), r.query(h, "AAAA"))
        ips = list(dict.fromkeys(a.records + aaaa.records))
        item = {"host": h, "ips": ips, "cname": cname.records[0] if cname.ok else None, "answers": None, "authoritative": None}
        pub = [ip for ip in ips if is_public_ip(ip)]
        if pub:
            async with sem:
                q = await r.query_at(pub[0], domain, "SOA")
            item["answers"] = q.status in ("ok", "noanswer")
            item["authoritative"] = bool(q.aa) and q.status == "ok"
            item["probe_status"] = q.status
        return item

    items = await asyncio.gather(*(one(h) for h in hosts))
    groups = {_prefix_key(ip) for i in items for ip in i["ips"]}
    n = len(hosts)
    if n < 2:
        res.add("ns_single", "fail", "Only one nameserver",
                "If your only nameserver is down, your website AND email disappear. Registries and best practice (RFC 2182) require at least two, "
                "on separate networks.", ["Add a second nameserver at your DNS provider and registrar (providers normally give you two or more)."])
    for i in items:
        if i["cname"]:
            res.add("ns_cname", "fail", f"Nameserver {i['host']} is an alias (CNAME)", "Nameserver names must have address records directly, not be aliases (RFC 2181).",
                    [f"Use the real name {i['cname']} as the nameserver."], host=i["host"])
        elif not i["ips"]:
            res.add("ns_no_address", "fail", f"Nameserver {i['host']} has no IP address",
                    "The delegation names a server that cannot be found, so resolvers cannot use it.",
                    ["Fix the nameserver name at your registrar, or add the missing A/AAAA record (glue)."], host=i["host"])
        elif i["answers"] is False or (i["answers"] and not i["authoritative"]):
            res.add("ns_lame", "fail", f"Nameserver {i['host']} does not answer for {domain}",
                    "This server is listed for your domain but did not give an authoritative answer (no reply, refused or not set up for the zone). "
                    "This is called a lame delegation: some lookups are slow or fail.",
                    [f"Make sure {i['host']} hosts the zone {domain} (is the zone created there?).",
                     "Or remove it from the nameserver list at your registrar if you no longer use that DNS provider."], host=i["host"],
                    probe=i.get("probe_status"))
    if n >= 2 and len(groups) == 1 and all(i["ips"] for i in items):
        res.add("ns_same_subnet", "warn", "All nameservers are in the same network block",
                "All your nameservers sit in one /24 (IPv4) or /48 (IPv6) block. One network outage or routing problem takes all of them down at once.",
                ["Use at least one nameserver in a different network, ideally from a second provider."], prefixes=sorted(groups))
    if n >= 2 and not any(f.id.startswith("ns_") for f in res.findings):
        res.add("ns_ok", "pass", f"{n} nameservers, all answering", "Your DNS has redundancy and every nameserver answered for the zone.")
    return {"count": n, "servers": items, "networks": sorted(groups)}


def _sub(findings, prefix: str) -> int:
    s = 100
    for f in findings:
        if f.id.startswith(prefix):
            if f.status == "fail":
                s -= 35
            elif f.status == "warn":
                s -= 12
            elif f.details.get("optional"):
                s -= 10
    return max(0, s)


async def check(domain: str, resolver: Resolver | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    res = CheckResult("dnsrec", domain)
    t0 = time.perf_counter()
    answers = await asyncio.gather(*(r.query(domain, t) for t in RTYPES), r.query(domain, "DS"), r.query(domain, "DNSKEY"),
                                   r.query(domain, "SOA", dnssec=True))
    res.timings_ms["records"] = round((time.perf_counter() - t0) * 1000, 1)
    by = dict(zip(RTYPES, answers[:8]))
    ds, dnskey, soa_v = answers[8], answers[9], answers[10]
    if all(a.status == "nxdomain" for a in by.values()):
        res.add("dns_nxdomain", "fail", "This domain does not exist", f"{domain} has no DNS records (NXDOMAIN).",
                ["Check the spelling, and that the domain is registered and delegated to working nameservers."])
        res.data = {"records": {}, "ns": None, "soa": None, "caa": None, "dnssec": None}
        return res.finalize("Domain does not exist.")
    if all(a.failed for a in by.values()):
        return error_result("dnsrec", domain, "All DNS lookups failed or timed out.")
    res.data = {"records": {t: a.records for t, a in by.items()}, "ttl": {t: a.ttl for t, a in by.items() if a.ttl is not None}}

    # --- CNAME at apex ---
    if by["CNAME"].ok and (by["SOA"].ok or by["NS"].ok or by["MX"].ok):
        res.add("dns_cname_apex", "fail", "A CNAME at the top of the domain",
                "A CNAME cannot exist next to the SOA/NS/MX records every domain needs, so mail and other records break unpredictably (RFC 1034).",
                ["Replace the CNAME at the root with A/AAAA records, or use your DNS provider's ALIAS/ANAME/CNAME-flattening feature."])

    # --- zone apex? ---
    soa_rec = parse_soa(by["SOA"].records[0]) if by["SOA"].ok else None
    ns_hosts = sorted({h.rstrip(".").lower() for h in by["NS"].records})
    res.data["soa"] = soa_rec
    if soa_rec is None and not ns_hosts:
        res.add("dns_not_apex", "info", f"{domain} is not the top of a DNS zone",
                "There are no SOA/NS records at this exact name, so it is a sub-domain inside a bigger zone. NS and SOA checks do not apply.",
                ["Enter the main domain (for example example.com) to check nameservers, SOA and DNSSEC."])
        res.data["ns"] = None
    else:
        if not ns_hosts:
            res.add("ns_missing", "fail", "No NS records found", "The zone has an SOA but the resolver could not find NS records for it.",
                    ["Check the nameserver settings at your registrar and DNS provider."])
            res.data["ns"] = None
        else:
            res.data["ns"] = await _check_ns(r, domain, ns_hosts, res)
    # --- SOA ---
    if soa_rec:
        fmt = serial_format(soa_rec["serial"])
        soa_rec["serial_format"] = fmt
        res.add("soa_serial", "info", f"SOA serial {soa_rec['serial']} ({'date-based YYYYMMDDnn' if fmt == 'date' else 'unix timestamp' if fmt == 'unix-timestamp' else 'counter'})",
                "The serial number must increase every time the zone changes so secondary servers pick up the update. Any scheme is fine as long as it only grows.")
        bad = []
        for k, (lo, hi) in SOA_RANGES.items():
            v = soa_rec[k]
            if not lo <= v <= hi:
                bad.append(f"{k}={v} (recommended {lo}-{hi})")
        if soa_rec["retry"] >= soa_rec["refresh"]:
            bad.append(f"retry={soa_rec['retry']} should be smaller than refresh={soa_rec['refresh']}")
        if bad:
            res.add("soa_timers", "warn", "SOA timers outside the usual ranges",
                    "These timers control how often secondary servers check for changes and how long negative answers are cached: " + "; ".join(bad) +
                    ". Values far outside the ranges work, but can cause slow updates or long outages if a server is down (RFC 1912, RIPE-203).",
                    ["Ask your DNS provider to use typical values, or change them in your DNS panel if it allows."],
                    fix_record=f"{domain}. IN SOA {soa_rec['mname']}. {soa_rec['rname']}. {soa_rec['serial']} 7200 3600 1209600 3600", problems=bad)
        else:
            res.add("soa_ok", "pass", "SOA timers look sane", "Refresh, retry, expire and negative-cache values are in the recommended ranges.")
    # --- CAA ---
    caa = parse_caa(by["CAA"].records)
    allowed = sorted({c["ca"] for c in caa if c.get("tag") in ("issue", "issuewild") and c["ca"]})
    res.data["caa"] = {"records": caa, "allowed_cas": [{"domain": a, "name": CA_NAMES.get(a)} for a in allowed],
                       "no_issuance": any(c.get("tag") == "issue" and not c.get("ca") for c in caa),
                       "iodef": [c["value"] for c in caa if c.get("tag") == "iodef"]}
    if not caa:
        res.add("caa_missing", "info", "No CAA record (optional)",
                "A CAA record lists which certificate authorities may issue HTTPS certificates for your domain. Without it any CA may. "
                "It is a cheap extra safeguard against mis-issued certificates.",
                ["Add a CAA record for the CA you use (for example Let's Encrypt)."],
                fix_record=f'{domain}.  IN CAA  0 issue "letsencrypt.org"', optional=True)
    else:
        bad = [c for c in caa if not c["valid"]]
        crit = [c for c in caa if c.get("valid") and c["flags"] & 128 and c["tag"] not in KNOWN_CAA_TAGS]
        if bad:
            res.add("caa_invalid", "fail", "A CAA record cannot be parsed", "CAA records look like: 0 issue \"ca.example\".", ["Fix or delete the broken record."],
                    records=[c["raw"] for c in bad])
        if crit:
            res.add("caa_critical_unknown", "warn", "A CAA record has the critical flag on an unknown tag",
                    "CAs must refuse to issue certificates if they do not understand a critical property.", ["Remove the critical flag (128) or the tag."],
                    tags=[c["tag"] for c in crit])
        if allowed:
            names = [f"{CA_NAMES.get(a, a)}" for a in allowed]
            res.add("caa_ok", "pass", f"Certificates limited to: {', '.join(names)}",
                    "Only these certificate authorities may issue certificates for the domain. Make sure the CA you actually use is on this list, "
                    "or renewals will fail.")
        elif res.data["caa"]["no_issuance"]:
            res.add("caa_no_issuance", "warn", "CAA forbids all certificate issuance",
                    "issue \";\" means no CA may issue certificates. That is only right if the domain must never get a certificate.",
                    ["Add an issue record for your CA if you need HTTPS certificates."])
        if not res.data["caa"]["iodef"]:
            res.add("caa_no_iodef", "info", "No iodef contact in CAA", "An iodef record lets CAs tell you about refused or suspicious requests.",
                    [f'Optional: {domain}.  IN CAA  0 iodef "mailto:security@{domain}"'])
    # --- DNSSEC ---
    has_ds, has_key = ds.ok, dnskey.ok
    ad = bool(soa_v.ad)
    state = "unsigned"
    if has_ds and has_key:
        state = "signed" if ad else "unverified"
    elif has_ds and not has_key:
        state = "broken"
    elif has_key and not has_ds:
        state = "partial"
    if soa_v.status == "servfail" and has_ds:
        state = "broken"
    res.data["dnssec"] = {"state": state, "ds": ds.records, "dnskey_count": len(dnskey.records), "ad": ad}
    if state == "signed":
        res.add("dnssec_signed", "pass", "DNSSEC is on and validates", "Answers for this domain are cryptographically signed and our resolver verified them.")
    elif state == "unverified":
        res.add("dnssec_unverified", "info", "DNSSEC records exist, validation not confirmed",
                "A DS record (at the registry) and a DNSKEY are published, but the resolver used here did not confirm validation (it may not validate DNSSEC). "
                "Use a validating resolver such as 1.1.1.1 to be sure.")
    elif state == "broken":
        res.add("dnssec_broken", "fail", "DNSSEC looks broken",
                "The registry publishes a DS record for the domain but the zone's signatures do not match (no DNSKEY, or validation fails). "
                "Resolvers that check DNSSEC (Google, Cloudflare, many ISPs) will then return errors for your domain, taking website and email offline for those users.",
                ["Quickest fix: remove the DS record at your registrar (this turns DNSSEC off).",
                 "Proper fix: make your DNS provider sign the zone again, then publish the new DS record from them at the registrar."])
    elif state == "partial":
        res.add("dnssec_partial", "warn", "The zone is signed but not linked to the registry",
                "The nameservers publish DNSSEC keys but there is no DS record at the registry, so nobody validates the signatures. No harm, no benefit.",
                ["Copy the DS record from your DNS provider into your registrar's DNSSEC settings."])
    else:
        res.add("dnssec_unsigned", "info", "DNSSEC is not enabled (optional)",
                "DNSSEC signs your DNS answers so they cannot be forged on the way. Most domains do not use it; it is a hardening step, not a requirement.",
                ["If your DNS provider supports DNSSEC, enable it there, then add the DS record they give you at your registrar."], optional=True)
    res.data["scores"] = {k: _sub(res.findings, p) for k, p in (("ns", "ns_"), ("soa", "soa_"), ("caa", "caa_"), ("dnssec", "dnssec_"))}
    nfail = sum(f.status == "fail" for f in res.findings)
    nwarn = sum(f.status == "warn" for f in res.findings)
    ns_n = (res.data.get("ns") or {}).get("count")
    summary = (f"{ns_n} nameserver(s), " if ns_n else "") + f"DNSSEC {state}" + (f"; {nfail} problem(s)" if nfail else "") + (f", {nwarn} warning(s)." if nwarn else ".")
    return res.finalize(summary)
