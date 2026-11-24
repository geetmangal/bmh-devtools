"""BIMI check (brand logo in the inbox): record at default._bimi.<domain>. The SVG and certificate are NOT fetched."""
from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

from app.core.mailcheck.dmarc import fetch_policy, org_domain, parse_tags
from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.resolver import Resolver, get_default_resolver


def _is_bimi(t: str) -> bool:
    return bool(re.match(r"^\s*v\s*=\s*BIMI1\s*(;|$)", t, re.I))


async def check(domain: str, resolver: Resolver | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    res = CheckResult("bimi", domain)
    t0 = time.perf_counter()
    found_at, rec = domain, None
    names = [domain] + ([org_domain(domain)] if org_domain(domain) != domain else [])
    for d in names:
        ans = await r.query(f"default._bimi.{d}", "TXT")
        if ans.failed:
            return error_result("bimi", domain, "DNS lookup for the BIMI record failed or timed out.")
        recs = [t for t in ans.records if _is_bimi(t)]
        if recs:
            found_at, rec = d, recs
            break
    res.timings_ms["lookup"] = round((time.perf_counter() - t0) * 1000, 1)
    res.data = {"record": None, "logo": None, "vmc": None, "found_at": None}
    if not rec:
        res.add("bimi_missing", "info", "No BIMI record (optional)",
                "BIMI shows your logo next to your emails in supporting inboxes (Gmail, Apple Mail, Yahoo). It is optional and only works "
                "after DMARC is enforced, so it is a later step.",
                ["First move DMARC to p=quarantine or p=reject at pct=100.",
                 f"Then publish a TXT record at default._bimi.{domain} that points to your logo (SVG Tiny PS, https).",
                 "Gmail also needs a Verified Mark Certificate (VMC) or Common Mark Certificate, linked with a= ."],
                fix_record=f'default._bimi.{domain}.  IN TXT  "v=BIMI1; l=https://{domain}/bimi/logo.svg; a="')
        return res.finalize("No BIMI record: your logo is not shown in inboxes.", score=85, status="info")
    if len(rec) > 1:
        res.add("bimi_multiple", "fail", "More than one BIMI record", "Receivers ignore BIMI when several records exist.",
                [f"Keep one TXT record at default._bimi.{found_at}."])
    tags = parse_tags(rec[0])
    logo, vmc = tags.get("l", ""), tags.get("a", "")
    res.data = {"record": rec[0], "logo": logo or None, "vmc": vmc or None, "found_at": found_at}
    if not logo and "l" in tags:
        res.add("bimi_declined", "info", "BIMI is switched off on purpose (empty l=)",
                "An empty l= tells receivers not to show any logo for this domain.")
    elif not logo:
        res.add("bimi_no_logo", "fail", "The record has no logo address (l=)", "Without l= there is no image to show.",
                ["Add l=https://your-site/logo.svg (SVG Tiny PS format)."])
    else:
        u = urlsplit(logo)
        if u.scheme != "https" or not u.hostname:
            res.add("bimi_logo_not_https", "fail", "The logo address must be an https URL",
                    "BIMI only accepts logos served over https.", [f"Serve the logo over https and use that address in l=."], logo=logo)
        elif not u.path.lower().endswith(".svg"):
            res.add("bimi_logo_not_svg", "warn", "The logo address does not end in .svg",
                    "BIMI logos must be SVG files in the SVG Tiny Portable/Secure profile. Other formats are not accepted.",
                    ["Convert the logo to SVG Tiny PS and publish that file."], logo=logo)
    if vmc:
        if urlsplit(vmc).scheme != "https":
            res.add("bimi_vmc_not_https", "fail", "The certificate address (a=) must be an https URL",
                    "The VMC/CMC file must be fetched over https.", ["Fix the a= address."], vmc=vmc)
    elif logo:
        res.add("bimi_no_vmc", "info", "No certificate (a=) linked",
                "Gmail only shows the logo when a Verified Mark Certificate or Common Mark Certificate is linked. Yahoo and Apple may show it without.",
                ["Buy a VMC/CMC from a supported authority (DigiCert, Entrust, SSL.com ...) and link its .pem file in a=."])
    # BIMI needs enforced DMARC
    pol = await fetch_policy(r, domain)
    tagsd = pol["tags"]
    p, sp = tagsd.get("p", "").lower(), tagsd.get("sp", "").lower()
    pct = tagsd.get("pct", "100")
    enforced = pol["status"] == "ok" and p in ("quarantine", "reject") and pct == "100" and (not sp or sp in ("quarantine", "reject"))
    res.data["dmarc_enforced"] = enforced
    if not enforced:
        why = ("there is no DMARC record" if pol["status"] != "ok" else
               f"DMARC is p={p or 'missing'}" + (f", pct={pct}" if pct != "100" else "") + (f", sp={sp}" if sp and sp not in ("quarantine", "reject") else ""))
        res.add("bimi_needs_dmarc", "warn", "BIMI will not show until DMARC is enforced",
                f"Receivers only display BIMI logos when DMARC is at quarantine or reject for 100% of mail. Right now {why}.",
                ["Follow the DMARC rollout: p=none, then quarantine (pct up to 100), then reject.", "BIMI starts working automatically once DMARC is enforced."])
    return res.finalize("BIMI record found." + ("" if enforced else " It will not display until DMARC is enforced."))
