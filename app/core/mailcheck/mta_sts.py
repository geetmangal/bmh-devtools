"""MTA-STS check (RFC 8461): TXT record, policy file over HTTPS, and whether the policy covers the real MX hosts.

The policy file is fetched through an injectable async fetcher. The production fetcher (``fetch_policy_http``)
reuses the SSRF guard of ``app.core.httpjson`` (https only, host must resolve to public addresses only), refuses
redirects (RFC 8461 forbids them), caps the body at 64 KB and the time at 5 s.
Known limitation (shared with httpjson): the guard resolves the name and httpx resolves it again when
connecting, so a DNS-rebinding race is theoretically possible; only a small text file is ever read."""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

from app.core.httpjson import FetchError, _guard
from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.mx import parse_mx
from app.core.mailcheck.resolver import Resolver, get_default_resolver

MAX_POLICY_BYTES = 64 * 1024
FETCH_TIMEOUT = 5.0


@dataclass
class PolicyResponse:
    status: int
    text: str
    content_type: str = ""


PolicyFetcher = Callable[[str], Awaitable[PolicyResponse]]


async def fetch_policy_http(url: str) -> PolicyResponse:
    """Production fetcher. Raises ``FetchError`` on any problem."""
    await _guard(url)
    hdrs = {"User-Agent": "BookMyHost-DevTools/1.2 (+https://bookmyhost.com/tools/)", "Accept": "text/plain"}
    buf = bytearray()
    try:
        async with asyncio.timeout(FETCH_TIMEOUT):
            async with httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=False, trust_env=False) as client:
                async with client.stream("GET", url, headers=hdrs) as r:
                    if 300 <= r.status_code < 400:
                        raise FetchError("the policy URL redirects; MTA-STS forbids redirects")
                    ctype = r.headers.get("content-type", "")
                    if r.status_code != 200:
                        raise FetchError(f"the policy URL returned HTTP {r.status_code}", r.status_code)
                    async for chunk in r.aiter_bytes():
                        buf += chunk
                        if len(buf) > MAX_POLICY_BYTES:
                            raise FetchError("the policy file is larger than 64 KB")
    except TimeoutError as exc:
        raise FetchError("the policy URL took too long to answer") from exc
    except httpx.HTTPError as exc:
        raise FetchError(f"could not connect over HTTPS ({type(exc).__name__}); check the certificate and host name") from exc
    return PolicyResponse(200, bytes(buf).decode("utf-8", "replace"), ctype)


def parse_policy(text: str) -> dict:
    """Parse an MTA-STS policy body into {version, mode, mx: [...], max_age, errors: [...] }."""
    out: dict = {"version": None, "mode": None, "mx": [], "max_age": None, "errors": [], "unknown": []}
    for line in text.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        k, sep, v = line.partition(":")
        if not sep:
            out["errors"].append(f"line without a colon: {line.strip()[:40]!r}")
            continue
        k, v = k.strip().lower(), v.strip()
        if k == "version":
            out["version"] = v
        elif k == "mode":
            out["mode"] = v.lower()
        elif k == "mx":
            out["mx"].append(v.lower().rstrip("."))
        elif k == "max_age":
            if v.isdigit():
                out["max_age"] = int(v)
            else:
                out["errors"].append(f"max_age is not a number: {v[:20]!r}")
        else:
            out["unknown"].append(k)
    return out


def mx_matches(pattern: str, host: str) -> bool:
    """RFC 8461 4.1: exact match, or '*.example.com' matching exactly one extra left-most label."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, rest = host.partition(".")
        return bool(head) and rest == pattern[2:]
    return pattern == host


async def check(domain: str, resolver: Resolver | None = None, fetcher: PolicyFetcher | None = None) -> CheckResult:
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    fetch = fetcher or fetch_policy_http
    res = CheckResult("mta_sts", domain)
    t0 = time.perf_counter()
    ans, mxans = await asyncio.gather(r.query(f"_mta-sts.{domain}", "TXT"), r.query(domain, "MX"))
    res.timings_ms["dns"] = round((time.perf_counter() - t0) * 1000, 1)
    if ans.failed:
        return error_result("mta_sts", domain, "DNS lookup for the MTA-STS record failed or timed out.")
    recs = [t for t in ans.records if re.match(r"^\s*v\s*=\s*STSv1\s*(;|$)", t, re.I)]
    res.data = {"txt": None, "id": None, "policy": None, "mx_hosts": [], "coverage": []}
    if not recs:
        res.add("mta_sts_missing", "info", "No MTA-STS (optional, recommended)",
                "Normally mail servers use encryption only if both sides agree, and an attacker on the network can strip it (a downgrade attack). "
                "MTA-STS lets you publish a rule that senders must use verified TLS to your mail servers.",
                [f"Get TLS certificates valid for your mail server names first (check SMTP TLS below).",
                 f"Publish the policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt (start with mode: testing).",
                 f"Add a TXT record _mta-sts.{domain} with v=STSv1; id=<a new number each time you change the policy>.",
                 "Also add TLS-RPT to receive failure reports, then switch the mode to enforce after a few weeks."],
                fix_record=f'_mta-sts.{domain}.  IN TXT  "v=STSv1; id={time.strftime("%Y%m%d%H%M%S", time.gmtime())}"')
        return res.finalize("No MTA-STS policy published.", score=75, status="info")
    if len(recs) > 1:
        res.add("mta_sts_multiple", "fail", "More than one MTA-STS TXT record", "Senders ignore MTA-STS when several records exist.",
                ["Keep one TXT record at _mta-sts."])
    tags = {}
    for part in recs[0].split(";"):
        k, _, v = part.partition("=")
        tags.setdefault(k.strip().lower(), v.strip())
    res.data["txt"], res.data["id"] = recs[0], tags.get("id")
    if not re.fullmatch(r"[A-Za-z0-9]{1,32}", tags.get("id", "")):
        res.add("mta_sts_bad_id", "fail", "The id= value is missing or invalid",
                "id must be 1-32 letters/digits. Senders re-download the policy only when the id changes.",
                ["Set id to a new value (for example a timestamp like 20261125T0900) each time you change the policy."],
                fix_record='v=STSv1; id=' + time.strftime("%Y%m%d%H%M%S", time.gmtime()))
    mx_hosts = [h for h in (p[1] for p in (parse_mx(x) for x in mxans.records) if p) if h != "."]
    res.data["mx_hosts"] = mx_hosts

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    t0 = time.perf_counter()
    try:
        pr = await fetch(url)
    except FetchError as exc:
        res.timings_ms["policy"] = round((time.perf_counter() - t0) * 1000, 1)
        res.add("mta_sts_policy_unreachable", "fail", "The policy file could not be fetched",
                f"The DNS record says MTA-STS is on, but {url} could not be read: {exc}. Senders that cannot get the policy cannot enforce it "
                "(and any cached policy keeps applying until it expires).",
                [f"Make sure mta-sts.{domain} has an A/AAAA record.",
                 f"Serve the file over HTTPS with a valid certificate for mta-sts.{domain} (not self-signed).",
                 "The path must be exactly /.well-known/mta-sts.txt and must answer 200 without any redirect."], url=url)
        return res.finalize("MTA-STS record exists but the policy file is not reachable.")
    res.timings_ms["policy"] = round((time.perf_counter() - t0) * 1000, 1)
    if pr.content_type and not pr.content_type.lower().startswith("text/plain"):
        res.add("mta_sts_content_type", "warn", f"The policy is served as {pr.content_type.split(';')[0]}",
                "RFC 8461 requires Content-Type text/plain. Some senders reject other types.", ["Serve the file as text/plain."])
    pol = parse_policy(pr.text)
    res.data["policy"] = {k: pol[k] for k in ("version", "mode", "mx", "max_age")}
    res.data["policy_text"] = pr.text[:2000]
    for e in pol["errors"]:
        res.add("mta_sts_policy_syntax", "fail", "The policy file has a syntax problem", e, ["Use lines like \"key: value\", one per line."])
    if pol["version"] != "STSv1":
        res.add("mta_sts_bad_version", "fail", "Policy version must be STSv1", f"Found {pol['version']!r}.", ["Start the file with: version: STSv1"])
    mode = pol["mode"]
    if mode not in ("enforce", "testing", "none"):
        res.add("mta_sts_bad_mode", "fail", "Policy mode must be enforce, testing or none", f"Found {mode!r}.", ["Use mode: testing first, then mode: enforce."])
    elif mode == "enforce":
        res.add("mta_sts_enforce", "pass", "Mode is enforce", "Supporting senders refuse to deliver unless TLS with a valid certificate is used.")
    elif mode == "testing":
        res.add("mta_sts_testing", "warn", "Mode is testing (not enforced)",
                "In testing mode senders report problems (if TLS-RPT is set) but still deliver, so you are not protected against downgrade attacks yet.",
                ["Check your TLS-RPT reports for a few weeks, then change to mode: enforce and bump the id."])
    else:
        res.add("mta_sts_none", "warn", "Mode is none (policy switched off)", "mode: none tells senders to forget MTA-STS for your domain.",
                ["Use mode: testing or enforce if you want protection."])
    if pol["max_age"] is None:
        res.add("mta_sts_no_max_age", "fail", "max_age is missing", "Senders need max_age (seconds) to know how long to cache the policy.",
                ["Add max_age: 604800 (one week) or more."])
    elif pol["max_age"] > 31557600:
        res.add("mta_sts_max_age_high", "warn", "max_age is more than one year", "RFC 8461 caps max_age at 31557600 seconds; senders cap it.",
                ["Use max_age: 31557600 or less."])
    elif pol["max_age"] < 86400:
        res.add("mta_sts_max_age_low", "warn", f"max_age is very short ({pol['max_age']} s)",
                "A policy cached for less than a day gives little protection against downgrade attacks.", ["Use at least 604800 (1 week); 2592000 (30 days) is common."])
    if mode in ("enforce", "testing") and not pol["mx"]:
        res.add("mta_sts_no_mx", "fail", "The policy lists no mx hosts", "With no mx: lines no server is acceptable, so in enforce mode all mail is refused.",
                ["Add one mx: line per mail server name (the same names as your MX records)."])
    # coverage
    coverage = []
    for h in mx_hosts:
        by = next((p for p in pol["mx"] if mx_matches(p, h)), None)
        coverage.append({"host": h, "covered_by": by, "covered": by is not None})
    res.data["coverage"] = coverage
    missing = [c["host"] for c in coverage if not c["covered"]]
    if missing and pol["mx"]:
        sev = "fail" if mode == "enforce" else "warn"
        res.add("mta_sts_mx_mismatch", sev, "The policy does not cover all your MX hosts",
                f"These MX hosts are not listed in the policy: {', '.join(missing)}. " +
                ("In enforce mode senders will refuse to deliver mail to them." if mode == "enforce" else "Once you switch to enforce, mail to them will be refused."),
                ["Add an mx: line for each of these hosts (a wildcard like *.example.com covers exactly one extra label).", "Bump the id in the TXT record so senders reload the policy."],
                fix_record="\n".join(["version: STSv1", f"mode: {mode if mode in ('enforce','testing') else 'testing'}"] + [f"mx: {h}" for h in mx_hosts]
                                     + [f"max_age: {pol['max_age'] or 604800}"]), missing=missing)
    unused = [p for p in pol["mx"] if mx_hosts and not any(mx_matches(p, h) for h in mx_hosts)]
    if unused:
        res.add("mta_sts_unused_mx", "info", "Policy lists hosts that are not in your MX records",
                f"Not used by any MX: {', '.join(unused)}. Harmless, but may be left over from an old setup.", ["Remove entries you no longer use."], unused=unused)
    if not mx_hosts:
        res.add("mta_sts_no_domain_mx", "warn", "The domain has no MX records", "MTA-STS only makes sense for a domain that receives mail.", ["Add MX records or remove MTA-STS."])
    return res.finalize(f"MTA-STS policy found, mode {mode or 'unknown'}.")
