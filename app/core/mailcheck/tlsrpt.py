"""SMTP TLS Reporting (RFC 8460): TXT record at _smtp._tls.<domain>."""
from __future__ import annotations

import re
import time

from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.resolver import Resolver, get_default_resolver


def parse(text: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in text.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags.setdefault(k.strip().lower(), v.strip())
    return tags


async def check(domain: str, resolver: Resolver | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    res = CheckResult("tlsrpt", domain)
    t0 = time.perf_counter()
    ans = await r.query(f"_smtp._tls.{domain}", "TXT")
    res.timings_ms["lookup"] = round((time.perf_counter() - t0) * 1000, 1)
    if ans.failed:
        return error_result("tlsrpt", domain, "DNS lookup for the TLS-RPT record failed or timed out.")
    recs = [t for t in ans.records if re.match(r"^\s*v\s*=\s*TLSRPTv1\s*(;|$)", t, re.I)]
    res.data = {"record": None, "rua": []}
    if not recs:
        res.add("tlsrpt_missing", "info", "No TLS-RPT record (optional)",
                "TLS reporting makes big mail providers send you a daily summary of problems they had delivering mail to you over an "
                "encrypted connection. It is most useful together with MTA-STS.",
                [f"Add a TXT record named _smtp._tls.{domain} with the value below (use a mailbox you read)."],
                fix_record=f'_smtp._tls.{domain}.  IN TXT  "v=TLSRPTv1; rua=mailto:tls-reports@{domain}"')
        return res.finalize("No TLS-RPT record: you receive no TLS delivery reports.", score=85, status="info")
    if len(recs) > 1:
        res.add("tlsrpt_multiple", "fail", "More than one TLS-RPT record", "Senders ignore TLS-RPT when several records exist.",
                ["Delete all but one."])
    tags = parse(recs[0])
    ruas = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    res.data = {"record": recs[0], "rua": ruas}
    if not ruas:
        res.add("tlsrpt_no_rua", "fail", "The record has no report address (rua=)", "Without rua= nobody knows where to send the reports.",
                [f"Add rua=mailto:tls-reports@{domain}."], fix_record=f"v=TLSRPTv1; rua=mailto:tls-reports@{domain}")
    bad = [u for u in ruas if not (re.match(r"^mailto:[^@\s]+@[^@\s]+$", u, re.I) or re.match(r"^https://[^\s]+$", u, re.I))]
    if bad:
        res.add("tlsrpt_bad_rua", "fail", "Report address must be mailto: or https:",
                "Only mailto:name@domain or an https:// URL are allowed in rua=.", ["Fix these values."], uris=bad)
    if not res.findings:
        res.add("tlsrpt_ok", "pass", "TLS-RPT is set up", f"Reports go to {', '.join(ruas)}.")
    return res.finalize("TLS-RPT record found." if not res.has("tlsrpt_no_rua") else "TLS-RPT record is incomplete.")
