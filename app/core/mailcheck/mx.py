"""MX check: records by priority, address + PTR + FCrDNS per mail host, provider detection."""
from __future__ import annotations

import asyncio
import ipaddress
import time

from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.resolver import Resolver, get_default_resolver
from app.core.validate import is_ip_literal, is_public_ip

MAX_HOSTS = 10
MAX_IPS_PER_HOST = 6

# (provider name, hostname suffixes). First match wins. Suffixes start with a dot and are matched against the
# lower-cased MX hostname.
PROVIDERS: list[tuple[str, tuple[str, ...]]] = [
    ("Google Workspace", (".google.com", ".googlemail.com")),
    ("Microsoft 365", (".mail.protection.outlook.com", ".mx.microsoft", ".outlook.com")),
    ("Zoho Mail", (".zoho.com", ".zoho.in", ".zoho.eu", ".zoho.com.au", ".zoho.jp", ".zohomail.com")),
    ("Proton Mail", (".protonmail.ch", ".proton.me")),
    ("Fastmail", (".messagingengine.com",)),
    ("Yahoo Mail", (".yahoodns.net",)),
    ("Mimecast", (".mimecast.com", ".mimecast.co.za", ".mimecast-offshore.com")),
    ("Proofpoint", (".pphosted.com", ".ppe-hosted.com")),
    ("Barracuda", (".barracudanetworks.com", ".barracuda.com")),
]


def detect_provider(host: str, domain: str | None = None) -> str | None:
    """Name the mail provider from the MX hostname, or None if unknown."""
    h = "." + host.lower().rstrip(".")
    if h.startswith(".inbound-smtp.") and h.endswith(".amazonaws.com"):
        return "Amazon SES (inbound)"
    for name, suffixes in PROVIDERS:
        if any(h.endswith(s) for s in suffixes):
            return name
    if domain:
        d = "." + domain.lower().rstrip(".")
        if h == d or h.endswith(d):
            return "Self-hosted / cPanel"
    return None


def parse_mx(record: str) -> tuple[int, str] | None:
    parts = record.split()
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1].rstrip(".").lower() if parts[1] != "." else "."


async def _host_info(r: Resolver, host: str) -> dict:
    cname, a, aaaa = await asyncio.gather(r.query(host, "CNAME"), r.query(host, "A"), r.query(host, "AAAA"))
    item: dict = {"host": host, "cname": cname.records[0].rstrip(".") if cname.ok else None,
                  "exists": a.exists or aaaa.exists, "addresses": [], "lookup_error": a.failed and aaaa.failed}
    ips = list(dict.fromkeys(a.records + aaaa.records))[:MAX_IPS_PER_HOST]

    async def addr(ip: str) -> dict:
        fam = ipaddress.ip_address(ip).version
        entry = {"ip": ip, "family": fam, "public": is_public_ip(ip), "ptr": [], "fcrdns": False}
        if not entry["public"]:
            return entry
        ptr = await r.query(ipaddress.ip_address(ip).reverse_pointer, "PTR")
        entry["ptr"] = [p.rstrip(".").lower() for p in ptr.records][:3]
        for name in entry["ptr"]:
            fwd = await r.query(name, "AAAA" if fam == 6 else "A")
            if any(_same_ip(x, ip) for x in fwd.records):
                entry["fcrdns"] = True
                break
        return entry

    item["addresses"] = list(await asyncio.gather(*(addr(ip) for ip in ips)))
    return item


def _same_ip(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


async def check(domain: str, resolver: Resolver | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    res = CheckResult("mx", domain)
    t0 = time.perf_counter()
    mxq = await r.query(domain, "MX")
    res.timings_ms["mx_query"] = round((time.perf_counter() - t0) * 1000, 1)

    if mxq.status == "nxdomain":
        res.add("mx_domain_missing", "fail", "This domain does not exist",
                f"{domain} has no DNS records at all, so no mail can be delivered to it.",
                ["Check the spelling of the domain.", "If you own it, make sure it is registered and its nameservers are set."])
        res.data = {"domain": domain, "mode": "none", "ladder": [], "provider": None}
        return res.finalize("Domain does not exist.")
    if mxq.failed:
        return error_result("mx", domain, f"DNS lookup for MX records failed ({mxq.status}).")

    parsed = sorted((p for p in (parse_mx(x) for x in mxq.records) if p), key=lambda p: (p[0], p[1]))
    data: dict = {"domain": domain, "mode": "mx", "ladder": [], "provider": None}

    # ---- no MX: implicit MX (RFC 5321 5.1) ----
    if not parsed:
        a, aaaa = await asyncio.gather(resolver_q(r, domain, "A"), resolver_q(r, domain, "AAAA"))
        if not (a.ok or aaaa.ok):
            res.add("mx_none", "fail", "No mail server is set up for this domain",
                    f"{domain} has no MX record and no A/AAAA record, so senders have nowhere to deliver mail.",
                    ["Add an MX record that points to your mail provider's mail server (they give you the exact value).",
                     "Example: priority 10, host mail.example.com. Hosts must be names, not IP addresses."])
            data["mode"] = "none"
            res.data = data
            return res.finalize("No MX record: this domain cannot receive email.")
        info = await _host_info(r, domain)
        data["mode"] = "implicit"
        data["ladder"] = [{"priority": 0, "implicit": True, "provider": None, **info}]
        res.add("mx_implicit", "warn", "No MX record: mail would go to the website's address",
                f"{domain} has no MX record. By an old fallback rule, senders will try the server in the A record "
                "(normally your web server), which usually does not run a mail server. Many senders and spam filters "
                "will reject or delay this mail.",
                ["Add an explicit MX record that points to your mail provider's server.",
                 "If you do not want mail on this domain, publish a null MX (priority 0, host \".\") so senders stop trying."],
                fix_record=f"{domain}.  IN MX  0 .   ; only if this domain should NOT receive email")
        res.data = data
        _addr_findings(res, data["ladder"], domain)
        return res.finalize("No MX record; falling back to the A record.")

    # ---- null MX (RFC 7505) ----
    if any(h == "." for _, h in parsed):
        if len(parsed) == 1 and parsed[0][0] == 0:
            data["mode"] = "null"
            data["applicable"] = False
            res.add("mx_null", "info", "This domain says it does not accept email",
                    "A \"null MX\" record (priority 0, host \".\") tells senders this domain never receives mail, "
                    "so they stop retrying immediately instead of waiting days.",
                    ["If this is intended, nothing to do (also publish SPF \"v=spf1 -all\" and DMARC p=reject).",
                     "If you do want email here, replace it with your provider's MX records."])
            res.data = data
            return res.finalize("Null MX: this domain deliberately does not receive email.", status="info", score=100)
        res.add("mx_null_mixed", "fail", "A null MX is mixed with real MX records",
                "RFC 7505 says a null MX must be the only MX record. Mixed with others, senders behave unpredictably.",
                ["Delete the \".\" MX record if you want email here, or delete all the other MX records if you do not."])
        parsed = [p for p in parsed if p[1] != "."]
        if not parsed:
            res.data = data
            return res.finalize("Invalid null MX.")

    hosts = parsed[:MAX_HOSTS]
    if len(parsed) > MAX_HOSTS:
        res.add("mx_many", "info", "Many MX records", f"Only the first {MAX_HOSTS} of {len(parsed)} were checked.")
    t0 = time.perf_counter()
    infos = []
    lit = [(p, h) for p, h in hosts if is_ip_literal(h)]
    names = [(p, h) for p, h in hosts if not is_ip_literal(h)]
    got = await asyncio.gather(*(_host_info(r, h) for _, h in names))
    res.timings_ms["hosts"] = round((time.perf_counter() - t0) * 1000, 1)
    for (p, h), info in zip(names, got):
        infos.append({"priority": p, "provider": detect_provider(h, domain), **info})
    for p, h in lit:
        infos.append({"priority": p, "provider": None, "host": h, "cname": None, "exists": False,
                      "addresses": [], "lookup_error": False, "ip_literal": True})
        res.add("mx_ip_literal", "fail", f"MX points to an IP address ({h})",
                "An MX record must name a host (like mail.example.com), not an IP address. Many mail servers refuse to "
                "deliver to an MX that is an IP, so mail can bounce.",
                ["Create an A record (for example mail.example.com -> that IP).",
                 "Change the MX record to that host name."],
                fix_record=f"{domain}.  IN MX  {p} mail.{domain}.", host=h)
    infos.sort(key=lambda i: (i["priority"], i["host"]))
    data["ladder"] = infos
    provs = [i["provider"] for i in infos if i["provider"]]
    data["provider"] = provs[0] if provs else None
    data["providers"] = sorted(set(provs))
    _addr_findings(res, infos, domain)

    if len(set(provs)) > 1:
        res.add("mx_mixed_providers", "warn", "MX records from different mail providers",
                f"Your MX records point to {', '.join(sorted(set(provs)))}. Senders pick servers by priority, so some mail "
                "ends up at one provider and some at the other, which is rarely what you want.",
                ["Keep only the MX records of the provider where your mailboxes live.",
                 "A mail filter (Mimecast, Proofpoint, ...) in front of a mailbox provider is the one normal exception."])
    if len(infos) == 1 and not res.has("mx_ip_literal"):
        res.add("mx_single", "info", "Only one mail server",
                "With a single MX record, mail waits in the sender's queue if that server is down (it is normally retried "
                "for several days). Large providers run many servers behind one name, so this is usually fine.",
                ["For self-hosted mail, add a second MX with a higher priority number as a backup."])
    res.data = data
    ok = not any(f.status == "fail" for f in res.findings)
    if ok and not any(f.status == "warn" for f in res.findings):
        res.add("mx_ok", "pass", "Mail servers look good",
                f"{len(infos)} mail server(s) found" + (f", hosted by {data['provider']}." if data["provider"] else "."))
    return res.finalize(_summary(infos, data["provider"], res))


def resolver_q(r: Resolver, name: str, rtype: str):
    return r.query(name, rtype)


def _summary(infos: list[dict], provider: str | None, res: CheckResult) -> str:
    n = len(infos)
    base = f"{n} MX record{'s' if n != 1 else ''}" + (f" ({provider})" if provider else "")
    bad = [f for f in res.findings if f.status == "fail"]
    if bad:
        return f"{base}, but {len(bad)} problem{'s' if len(bad) != 1 else ''} will stop or slow mail delivery."
    warn = [f for f in res.findings if f.status == "warn"]
    return base + (f", with {len(warn)} thing(s) to improve." if warn else ", all resolving correctly.")


def _addr_findings(res: CheckResult, infos: list[dict], domain: str) -> None:
    for i in infos:
        host = i["host"]
        if i.get("ip_literal"):
            continue
        if i.get("cname"):
            res.add("mx_cname", "fail", f"MX host {host} is a CNAME alias",
                    "An MX record must point at a name that has address (A/AAAA) records directly, never at an alias (CNAME). "
                    "Some mail servers follow the alias, others refuse, so delivery becomes unreliable (RFC 2181).",
                    [f"Look up what {host} points to ({i['cname']}).",
                     f"Change the MX record to use {i['cname']} directly, or replace the alias with A/AAAA records."],
                    fix_record=f"{domain}.  IN MX  {i['priority']} {i['cname']}.", host=host, target=i["cname"])
        if i.get("lookup_error"):
            res.add("mx_host_dns_error", "warn", f"Could not look up {host}",
                    "The DNS lookup for this mail host timed out or failed, so we could not check it.",
                    ["Run the check again in a minute."], host=host)
            continue
        if not i["addresses"]:
            res.add("mx_unresolvable", "fail", f"MX host {host} has no IP address",
                    f"{host} has no A or AAAA record, so senders cannot find a server to connect to. Mail to this priority fails "
                    "and is retried or bounced.",
                    [f"Add an A record for {host} pointing to your mail server's IP, or fix the MX host name (typo?)."], host=host)
            continue
        provider = i.get("provider")
        for ad in i["addresses"]:
            if not ad["public"]:
                res.add("mx_private_ip", "fail", f"{host} points to a private or reserved address ({ad['ip']})",
                        "Private addresses (10.x, 192.168.x, 127.x, ...) only work inside your own network. "
                        "Mail from the internet cannot reach this server.",
                        [f"Change the DNS record for {host} to the server's public IP address.",
                         "If the server is behind a router/NAT, forward port 25 to it and use the public IP."],
                        host=host, ip=ad["ip"])
            elif provider is None or provider == "Self-hosted / cPanel":
                if not ad["ptr"]:
                    res.add("mx_no_ptr", "warn", f"{ad['ip']} has no reverse DNS (PTR)",
                            "Mail servers are expected to have a reverse DNS name. Many receivers treat a server without one as "
                            "suspicious. It matters most for mail this server sends out.",
                            [f"Ask whoever owns the IP {ad['ip']} (your hosting provider) to set its PTR record to {host}."],
                            host=host, ip=ad["ip"])
                elif not ad["fcrdns"]:
                    res.add("mx_fcrdns_mismatch", "warn", f"Reverse DNS of {ad['ip']} does not match",
                            f"The IP's reverse DNS says {', '.join(ad['ptr'])}, but that name does not point back to {ad['ip']}. "
                            "Spam filters check that the forward and reverse names agree (FCrDNS).",
                            [f"Make the name in the PTR record have an A/AAAA record with the same IP ({ad['ip']}).",
                             f"Or ask your host to set the PTR of {ad['ip']} to a name that already points to it."],
                            host=host, ip=ad["ip"], ptr=ad["ptr"])


def mx_addresses(data: dict, limit: int = 4) -> list[str]:
    """Public IPs of the MX hosts in priority order, IPv4 first, deduplicated (for DNSBL checks)."""
    ips: list[str] = []
    for item in data.get("ladder", []):
        for ad in item.get("addresses", []):
            if ad["public"] and ad["ip"] not in ips:
                ips.append(ad["ip"])
    ips.sort(key=lambda s: ":" in s)
    return ips[:limit]


def top_mx_host(data: dict) -> str | None:
    for item in data.get("ladder", []):
        if item.get("addresses") and any(a["public"] for a in item["addresses"]) and not item.get("ip_literal"):
            return item["host"]
    return None
