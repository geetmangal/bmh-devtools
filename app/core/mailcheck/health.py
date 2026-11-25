"""Domain health: run every check concurrently, stream results as they finish, then score.

Scoring model (all numbers live in the constants below so they are easy to audit):

1. Each check yields a 0-100 score (see ``CheckResult.finalize``: 100, minus 35 per fail, 12 per warn).
2. Six areas (the radar axes) are weighted averages of check scores (``AREA_COMPONENTS``). A component that is
   missing, errored or not applicable (SMTP test disabled, null-MX domain) is dropped and the rest renormalised.
3. The overall score is the weighted average of the available areas (``AREA_WEIGHTS``): authentication counts most
   because SPF/DKIM/DMARC decide inbox vs spam; mail delivery next.
4. Hard caps (``CAPS``) stop a good average hiding a critical problem, e.g. no SPF or DMARC cannot score above C,
   an open ``+all`` SPF, a broken DNSSEC or a serious blocklist listing cannot score above C/D.
5. Grade: A >= 90, B >= 80, C >= 70, D >= 60, else F.
The fix list contains every warn/fail finding, fails first, then ordered by CHECK_PRIORITY."""
from __future__ import annotations

import asyncio
import time
from typing import Any, AsyncIterator, Awaitable, Callable

from app.core import dnsbl, smtpcheck
from app.core.mailcheck import bimi, dkim, dmarc, dnsrec, mta_sts, mx, spf, tlsrpt
from app.core.mailcheck.models import CheckResult, clean_domain, error_result
from app.core.mailcheck.resolver import Resolver, get_default_resolver

CHECK_NAMES = ["mx", "spf", "dmarc", "dkim", "bimi", "mta_sts", "tlsrpt", "dnsrec", "dnsbl", "smtp"]
CHECK_PRIORITY = ["spf", "dmarc", "mx", "dnsbl", "dkim", "smtp", "dnsrec", "mta_sts", "tlsrpt", "bimi"]
DEFAULT_BUDGET = 25.0

AREA_LABELS = {"mail_delivery": "Mail delivery", "authentication": "Authentication", "security": "Security",
               "dns": "DNS", "reputation": "Reputation", "configuration": "Configuration"}
AREA_WEIGHTS = {"mail_delivery": 0.25, "authentication": 0.30, "security": 0.15, "dns": 0.10, "reputation": 0.10, "configuration": 0.10}
# component key -> weight. "dnsrec.X" reads data.scores.X of the DNS records check.
AREA_COMPONENTS: dict[str, dict[str, float]] = {
    "mail_delivery": {"mx": 0.6, "smtp": 0.4},
    "authentication": {"spf": 0.35, "dmarc": 0.45, "dkim": 0.20},
    "security": {"mta_sts": 0.35, "smtp": 0.25, "dnsrec.dnssec": 0.20, "dnsrec.caa": 0.20},
    "dns": {"dnsrec.ns": 0.6, "dnsrec.soa": 0.4},
    "reputation": {"dnsbl": 1.0},
    "configuration": {"dkim": 0.4, "bimi": 0.3, "tlsrpt": 0.3},
}
# (check, finding id prefix, max overall score, reason)
CAPS: list[tuple[str, str, int, str]] = [
    ("spf", "spf_missing", 79, "No SPF record"),
    ("dmarc", "dmarc_missing", 79, "No DMARC record"),
    ("spf", "spf_plus_all", 79, "SPF allows anyone to send (+all)"),
    ("spf", "spf_too_many_lookups", 79, "SPF exceeds the 10-lookup limit (SPF fails)"),
    ("spf", "spf_multiple", 79, "More than one SPF record (SPF fails)"),
    ("dnsrec", "dnssec_broken", 69, "DNSSEC is broken"),
    ("dnsrec", "ns_single", 79, "Only one nameserver"),
    ("mx", "mx_none", 59, "No mail server (MX)"),
    ("mx", "mx_domain_missing", 59, "Domain does not exist"),
    ("mx", "mx_unresolvable", 69, "An MX host does not resolve"),
    ("mx", "mx_private_ip", 69, "An MX host points to a private address"),
    ("dnsbl", "dnsbl_listed_zen_spamhaus_org", 69, "Listed on Spamhaus"),
]
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def grade_for(score: float) -> str:
    return next(g for lo, g in GRADES if score >= lo)


def _applicable(name: str, res: CheckResult | None, results: dict[str, CheckResult]) -> bool:
    if res is None or res.status == "error":
        return False
    if res.data.get("applicable") is False:
        return False
    mxr = results.get("mx")
    if mxr is not None and mxr.data.get("mode") == "null" and name in ("mx", "smtp", "dnsbl", "mta_sts", "tlsrpt"):
        return False
    return True


def _component(key: str, results: dict[str, CheckResult]) -> float | None:
    name, _, sub = key.partition(".")
    res = results.get(name)
    if not _applicable(name, res, results):
        return None
    if sub:
        return float(res.data.get("scores", {}).get(sub, res.score))
    return float(res.score)


def score_results(domain: str, results: dict[str, CheckResult]) -> dict[str, Any]:
    areas = []
    for key, comps in AREA_COMPONENTS.items():
        got = [(w, _component(c, results)) for c, w in comps.items()]
        got = [(w, s) for w, s in got if s is not None]
        score = round(sum(w * s for w, s in got) / sum(w for w, _ in got)) if got else None
        areas.append({"key": key, "label": AREA_LABELS[key], "score": score, "grade": grade_for(score) if score is not None else None,
                      "weight": AREA_WEIGHTS[key]})
    avail = [a for a in areas if a["score"] is not None]
    overall = round(sum(a["weight"] * a["score"] for a in avail) / sum(a["weight"] for a in avail)) if avail else 0
    capped_by = []
    for check, fid, cap, why in CAPS:
        res = results.get(check)
        if res and any(f.id.startswith(fid) and f.status in ("fail", "warn") for f in res.findings):
            capped_by.append({"reason": why, "cap": cap})
    both = {r["reason"] for r in capped_by}
    if {"No SPF record", "No DMARC record"} <= both:  # no email authentication at all
        capped_by.append({"reason": "No SPF and no DMARC", "cap": 69})
    if capped_by:
        overall = min(overall, min(c["cap"] for c in capped_by))
    fixes = []
    for name, res in results.items():
        for f in res.findings:
            if f.status in ("fail", "warn"):
                d = f.to_dict()
                d["check"] = name
                fixes.append(d)
    fixes.sort(key=lambda d: (d["status"] != "fail", CHECK_PRIORITY.index(d["check"]) if d["check"] in CHECK_PRIORITY else 99))
    counts = {"fail": 0, "warn": 0, "pass": 0}
    for res in results.values():
        for f in res.findings:
            if f.status in counts:
                counts[f.status] += 1
    return {
        "domain": domain, "score": overall, "grade": grade_for(overall), "areas": areas,
        "radar": [{"axis": a["label"], "key": a["key"], "score": a["score"]} for a in areas],
        "capped_by": capped_by, "fixes": fixes, "counts": counts,
        "checks": {n: {"status": r.status, "score": r.score, "summary": r.summary} for n, r in results.items()},
    }


def _na(check: str, domain: str, why: str) -> CheckResult:
    r = CheckResult(check, domain)
    r.data = {"applicable": False}
    return r.finalize(why, score=100, status="info")


Override = Callable[..., Awaitable[CheckResult]]


async def iter_health(domain: str, *, resolver: Resolver | None = None, dnsbl_resolver: Resolver | None = None,
                      policy_fetcher: mta_sts.PolicyFetcher | None = None, smtp_resolve: Callable | None = None,
                      dkim_selector: str | None = None, budget: float = DEFAULT_BUDGET,
                      overrides: dict[str, Override] | None = None) -> AsyncIterator[dict]:
    """Yield {"type": "check", "name", "result", "elapsed_ms"} as each check finishes, then {"type": "summary", ...}.
    ``overrides`` (tests) maps a check name to a zero-argument async callable returning a CheckResult."""
    domain = clean_domain(domain)
    r = resolver or get_default_resolver()
    ov = overrides or {}
    t_start = time.monotonic()

    async def mx_job() -> CheckResult:
        return await mx.check(domain, r)

    mx_task = asyncio.create_task(_guarded("mx", domain, ov.get("mx") or mx_job, budget), name="mx")

    async def dnsbl_job() -> CheckResult:
        m = await asyncio.shield(mx_task)
        ips = mx.mx_addresses(m.data, 4)
        if not ips:
            return _na("dnsbl", domain, "No public mail server IP to check.")
        return await dnsbl.check_many(ips, dnsbl_resolver)

    async def smtp_job() -> CheckResult:
        m = await asyncio.shield(mx_task)
        host = mx.top_mx_host(m.data)
        if not host:
            return _na("smtp", domain, "No reachable mail server to test.")
        return await smtpcheck.check(host, resolve_host=smtp_resolve)

    jobs: dict[str, Override] = {
        "spf": lambda: spf.check(domain, r), "dmarc": lambda: dmarc.check(domain, r),
        "dkim": lambda: dkim.check(domain, dkim_selector, r), "bimi": lambda: bimi.check(domain, r),
        "mta_sts": lambda: mta_sts.check(domain, r, policy_fetcher), "tlsrpt": lambda: tlsrpt.check(domain, r),
        "dnsrec": lambda: dnsrec.check(domain, r), "dnsbl": dnsbl_job, "smtp": smtp_job,
    }
    tasks: dict[asyncio.Task, str] = {mx_task: "mx"}
    for name, job in jobs.items():
        tasks[asyncio.create_task(_guarded(name, domain, ov.get(name) or job, budget), name=name)] = name
    results: dict[str, CheckResult] = {}
    pending = set(tasks)
    deadline = t_start + budget
    try:
        while pending:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            done, pending = await asyncio.wait(pending, timeout=left, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                name = tasks[t]
                results[name] = t.result()
                yield {"type": "check", "name": name, "result": results[name].to_dict(), "elapsed_ms": round((time.monotonic() - t_start) * 1000)}
        for t in list(pending):
            t.cancel()
            name = tasks[t]
            results[name] = error_result(name, domain, "This check did not finish within the time budget.")
            yield {"type": "check", "name": name, "result": results[name].to_dict(), "elapsed_ms": round((time.monotonic() - t_start) * 1000)}
    finally:
        for t in pending:
            t.cancel()
    ordered = {n: results[n] for n in CHECK_NAMES if n in results}
    yield {"type": "summary", "summary": score_results(domain, ordered), "elapsed_ms": round((time.monotonic() - t_start) * 1000)}


async def _guarded(name: str, domain: str, job: Override, budget: float) -> CheckResult:
    """Run one check; never raises (a crash becomes an error result so the others still finish)."""
    try:
        return await asyncio.wait_for(job(), budget)
    except asyncio.TimeoutError:
        return error_result(name, domain, "This check timed out.")
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        return error_result(name, domain, f"This check failed unexpectedly ({type(exc).__name__}).")


async def domain_health(domain: str, **kw: Any) -> dict[str, Any]:
    """Run everything and return {"domain", "checks": {name: result}, "summary": {...}}."""
    checks: dict[str, dict] = {}
    summary: dict = {}
    async for ev in iter_health(domain, **kw):
        if ev["type"] == "check":
            checks[ev["name"]] = ev["result"]
        else:
            summary = ev["summary"]
    return {"domain": summary.get("domain", domain), "checks": {n: checks[n] for n in CHECK_NAMES if n in checks}, "summary": summary}
